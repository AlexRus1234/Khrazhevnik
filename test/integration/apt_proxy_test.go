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

// E2E apt-прокси: httptest-upstream с мини-репозиторием → наш прокси
// → метаданные byte-exact (sha256 совпадает с upstream), .deb из кеша
// (upstream-счётчик пакета = 1 после двух запросов). Сессия 07.

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
	"khrazhevnik/internal/mod/ecosystem/apt"
	"khrazhevnik/internal/testutil"
)

// aptUpstream — httptest-сервер с мини-репо: один .deb и один
// Release-файл. Считает запросы по пути (для проверки кеша).
type aptUpstream struct {
	mu        atomic.Int64
	pkgBytes  []byte
	plusBytes []byte
	relBytes  []byte
	srv       *httptest.Server
}

func newAptUpstream(t *testing.T) *aptUpstream {
	t.Helper()
	u := &aptUpstream{
		pkgBytes:  []byte("DEB-CONTENT-100-bytes-padding-padding-padding-padding-padding!!"),
		plusBytes: []byte("DEB-GXX-CONTENT-100-bytes-padding-padding-padding-padding-padding!!"),
		relBytes:  []byte("Origin: Test\nLabel: Test\nSuite: stable\nDate: Sat, 22 Aug 2026 12:00:00 UTC\n"),
	}
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *aptUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Add(1)
	switch r.URL.Path {
	case "/debian/pool/main/a/app/app_1.0_amd64.deb":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.pkgBytes)
	case "/debian/pool/main/g/gcc-13/libstdc++6_13.2.0-7~deb12u1_amd64.deb":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.plusBytes)
	case "/debian/dists/stable/Release":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"rel-v1"`)
		_, _ = w.Write(u.relBytes)
	default:
		http.NotFound(w, r)
	}
}

func (u *aptUpstream) hits() int64 { return u.mu.Load() }

// aptTestStart — детерминированный момент для движка кеша и адаптера.
var aptTestStart = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func TestAptProxyByteExactAndCache(t *testing.T) {
	up := newAptUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(aptTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(aptTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 7, Name: "debian", Ecosystem: "apt",
		BaseURL: up.srv.URL + "/debian", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := apt.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"apt": adapter},
	})

	// Метаданные (mutable): byte-exact c upstream, sha256 совпадает.
	relSHA := sha256.Sum256(up.relBytes)
	wantRelHex := hex.EncodeToString(relSHA[:])
	rec := aptGet(t, h, "/apt/debian/dists/stable/Release")
	if rec.Code != http.StatusOK {
		t.Fatalf("Release: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantRelHex {
		t.Fatalf("Release sha256 = %s, хочу %s (byte-exact нарушен)", got, wantRelHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("Release первый X-Cache = %q, хочу MISS", got)
	}

	// Пакет (immutable): первый запрос — upstream-промах, второй — HIT.
	pkgSHA := sha256.Sum256(up.pkgBytes)
	wantPkgHex := hex.EncodeToString(pkgSHA[:])
	rec = aptGet(t, h, "/apt/debian/pool/main/a/app/app_1.0_amd64.deb")
	if rec.Code != http.StatusOK {
		t.Fatalf(".deb первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPkgHex {
		t.Fatalf(".deb sha256 = %s, хочу %s (byte-exact нарушен)", got, wantPkgHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf(".deb первый X-Cache = %q, хочу MISS", got)
	}
	upstreamHitsAfterFirst := up.hits()

	// второй запрос пакета — из кеша, upstream не дёргается
	rec = aptGet(t, h, "/apt/debian/pool/main/a/app/app_1.0_amd64.deb")
	if rec.Code != http.StatusOK {
		t.Fatalf(".deb второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf(".deb второй X-Cache = %q, хочу HIT", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPkgHex {
		t.Fatalf(".deb второй sha256 = %s, хочу %s", got, wantPkgHex)
	}
	if up.hits() != upstreamHitsAfterFirst {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (пакет не из кеша)", up.hits(), upstreamHitsAfterFirst)
	}
}

// aptGet — GET к публичному роутеру.
func aptGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestAptProxyPlusTildeKey — реальные имена пакетов с «+»/«~» (сессия 65)
// проходят прокси: 200, byte-exact, повторный запрос — HIT из кеша.
func TestAptProxyPlusTildeKey(t *testing.T) {
	up := newAptUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(aptTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(aptTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 7, Name: "debian", Ecosystem: "apt",
		BaseURL: up.srv.URL + "/debian", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := apt.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"apt": adapter},
	})

	const path = "/apt/debian/pool/main/g/gcc-13/libstdc++6_13.2.0-7~deb12u1_amd64.deb"
	wantHex := sha256Hex(up.plusBytes)

	rec := aptGet(t, h, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("первый запрос: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantHex {
		t.Fatalf("sha256 = %s, хочу %s (byte-exact нарушен)", got, wantHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("первый X-Cache = %q, хочу MISS", got)
	}
	hitsAfterFirst := up.hits()

	rec = aptGet(t, h, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("второй запрос: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("второй X-Cache = %q, хочу HIT", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantHex {
		t.Fatalf("второй sha256 = %s, хочу %s", got, wantHex)
	}
	if up.hits() != hitsAfterFirst {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (не из кеша)", up.hits(), hitsAfterFirst)
	}
}

// sha256Hex — hex от sha256 байт (для byte-exact проверки).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
