// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build integration

// E2E nix-прокси: httptest-upstream с мини-nix-binary-cache
// (1 narinfo + 1 nar.xz + nix-cache-info) → наш прокси → narinfo
// byte-exact (sha256 совпадает с upstream), nar.xz из кеша (upstream-
// счётчик пакета = 1 после двух запросов). 404 на narinfo — штатная
// ситуация nix-клиента (перебор substituter'ов): отдаётся корректный 404
// (не 502) и negative-cached (повтор не дёргает upstream). Сессия 13.
//
// nix-совместимость проверяется руками (шаги — в коммите сессии 13 и
// docs/func/ru/ecosystems/nix.md):
//
//	khrazhevnik -add-remote nix/cache=https://cache.nixos.org
//	# /etc/nix/nix.conf:
//	# substituters = http://localhost:29202/nix/cache https://cache.nixos.org
//	# trusted-public-keys = cache.nixos.org-1:... (остаётся от upstream)
//	nix-shell -p hello --substituters http://localhost:29202/nix/cache

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/nix"
	"khrazhevnik/internal/testutil"
)

// nixHash — синтетический 32-символьный nix-base32 хеш store path
// (алфавит nix без e/o/t/u — как у реального nix; hex-хеши не
// матчатся классификацией сессии 33).
const nixHash = "x0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y"

// nixUpstream — httptest-сервер с мини-nix-binary-cache: narinfo,
// nar.xz и nix-cache-info. Считает запросы к upstream.
type nixUpstream struct {
	mu        atomic.Int64
	narinfo   []byte
	nar       []byte
	cacheInfo []byte
	srv       *httptest.Server
}

func newNixUpstream(t *testing.T) *nixUpstream {
	t.Helper()
	u := &nixUpstream{
		nar:       []byte("NIX-NAR-CONTENT-100-bytes-padding-padding-padding-padding!"),
		cacheInfo: []byte("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"),
	}
	// narinfo реального вида: 5 полей + Sig. URL ссылает на nar/<hash>.nar.xz.
	u.narinfo = []byte("StorePath: /nix/store/" + nixHash + "-hello-2.12.1\n" +
		"URL: nar/" + nixHash + ".nar.xz\n" +
		"Compression: xz\n" +
		"FileHash: sha256:" + nixHash + nixHash + "\n" +
		"FileSize: 100\n" +
		"NarHash: sha256:" + nixHash + nixHash + "\n" +
		"NarSize: 200\n" +
		"References: \n" +
		"Deriver: " + nixHash + "-hello-2.12.1.drv\n" +
		"Sig: cache.example.org-1:" + nixHash + nixHash + nixHash + nixHash + "=\n")
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *nixUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Add(1)
	switch r.URL.Path {
	case "/cache/" + nixHash + ".narinfo":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"narinfo-v1"`)
		_, _ = w.Write(u.narinfo)
	case "/cache/nar/" + nixHash + ".nar.xz":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.nar)
	case "/cache/nix-cache-info":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(u.cacheInfo)
	default:
		http.NotFound(w, r)
	}
}

func (u *nixUpstream) hits() int64 { return u.mu.Load() }

var nixTestStart = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func TestNixProxyByteExactAndCache(t *testing.T) {
	up := newNixUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(nixTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(nixTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 17, Name: "cache", Ecosystem: "nix",
		BaseURL: up.srv.URL + "/cache", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := nix.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"nix": adapter},
	})

	// narinfo (mutable): byte-exact с upstream, sha256 совпадает.
	narinfoSHA := sha256.Sum256(up.narinfo)
	wantNarinfoHex := hex.EncodeToString(narinfoSHA[:])
	rec := nixGet(t, h, "/nix/cache/"+nixHash+".narinfo")
	if rec.Code != http.StatusOK {
		t.Fatalf("narinfo: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantNarinfoHex {
		t.Fatalf("narinfo sha256 = %s, хочу %s (byte-exact нарушен)", got, wantNarinfoHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("narinfo первый X-Cache = %q, хочу MISS", got)
	}

	// nar.xz (immutable): первый запрос — upstream-промах, второй — HIT.
	narSHA := sha256.Sum256(up.nar)
	wantNarHex := hex.EncodeToString(narSHA[:])
	narPath := "/nix/cache/nar/" + nixHash + ".nar.xz"
	rec = nixGet(t, h, narPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("nar первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantNarHex {
		t.Fatalf("nar sha256 = %s, хочу %s (byte-exact нарушен)", got, wantNarHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("nar первый X-Cache = %q, хочу MISS", got)
	}
	hitsAfterFirst := up.hits()

	// второй запрос nar — из кеша, upstream не дёргается
	rec = nixGet(t, h, narPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("nar второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("nar второй X-Cache = %q, хочу HIT", got)
	}
	if up.hits() != hitsAfterFirst {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (nar не из кеша)", up.hits(), hitsAfterFirst)
	}
}

// TestNixProxy404NegativeCached — 404 на narinfo (штатный перебор
// substituter'ов) отдаётся как 404 (не 502) и negative-cached: повтор
// не дёргает upstream; после истечения NegativeTTL404 — снова идёт
// upstream.
func TestNixProxy404NegativeCached(t *testing.T) {
	up := newNixUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(nixTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(nixTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 17, Name: "cache", Ecosystem: "nix",
		BaseURL: up.srv.URL + "/cache", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := nix.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"nix": adapter},
	})

	missingPath := "/nix/cache/ffffffffffffffffffffffffffffffff.narinfo"

	// первый запрос — upstream 404, прокси отдаёт 404 (не 502).
	rec := nixGet(t, h, missingPath)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("отсутствующий narinfo: код %d, хочу 404 (не 502)", rec.Code)
	}
	hitsAfterFirst := up.hits()
	if hitsAfterFirst != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (первый 404)", hitsAfterFirst)
	}

	// повтор в окне negative — upstream не дёргается.
	rec = nixGet(t, h, missingPath)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("повторный narinfo: код %d, хочу 404", rec.Code)
	}
	if got := up.hits(); got != hitsAfterFirst {
		t.Errorf("upstream получил %d запросов после negative, хочу %d (negative-cache не сработал)", got, hitsAfterFirst)
	}

	// TTL negative истёк — снова идём upstream (404 авторитетен, но
	// переспрашиваем по расписанию, как движок кеша).
	clock.Advance(5*time.Minute + time.Second)
	rec = nixGet(t, h, missingPath)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("после TTL narinfo: код %d, хочу 404", rec.Code)
	}
	if got := up.hits(); got != hitsAfterFirst+1 {
		t.Errorf("upstream после истечения negative: %d, хочу %d (должен переспросить)", got, hitsAfterFirst+1)
	}
}

func nixGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
