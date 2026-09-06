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
	"strconv"
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

// TestAptProxyEncodedPlus — apt-клиент шлёт «+» в пути как %2b
// (CI-факт №4 distro-test: apt-get install падал 400 на
// libnl-3-200_3.7.0-0.2+b1). Экранированное написание должно давать
// тот же объект кеша, что и сырое «+» (upstream-счётчик = 1);
// двойное кодирование — 400 без кеш-загрязнения. httptest.NewRequest
// с %-таргетом воспроизводит провод: chi берёт RawPath.
func TestAptProxyEncodedPlus(t *testing.T) {
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

	const escaped = "/apt/debian/pool/main/g/gcc-13/libstdc%2b%2b6_13.2.0-7~deb12u1_amd64.deb"
	const raw = "/apt/debian/pool/main/g/gcc-13/libstdc++6_13.2.0-7~deb12u1_amd64.deb"
	wantHex := sha256Hex(up.plusBytes)

	rec := aptGet(t, h, escaped)
	if rec.Code != http.StatusOK {
		t.Fatalf("%%2b-запрос: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantHex {
		t.Fatalf("%%2b-запрос sha256 = %s, хочу %s (byte-exact нарушен)", got, wantHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("%%2b-запрос X-Cache = %q, хочу MISS", got)
	}
	hitsAfterFirst := up.hits()

	// Сырое «+» — тот же объект кеша: HIT, upstream не дёргается.
	rec = aptGet(t, h, raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw-запрос: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("raw-запрос X-Cache = %q, хочу HIT (один объект на оба написания)", got)
	}
	if up.hits() != hitsAfterFirst {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d", up.hits(), hitsAfterFirst)
	}

	// Двойное кодирование: %252b декодится в «%2b» с «%» — whitelist
	// ValidateKey режет fail-closed → 400.
	rec = aptGet(t, h, "/apt/debian/pool/main/g/gcc-13/libstdc%252b%252b6_13.2.0-7~deb12u1_amd64.deb")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("%%252b-запрос = %d, хочу 400", rec.Code)
	}
}

// sha256Hex — hex от sha256 байт (для byte-exact проверки).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestProxyHitHeadersIdentityEncoding — E2E-контракт заголовков HIT
// (сессия 69): первый запрос — MISS, второй — HIT; Content-Type,
// Content-Length и ETag от upstream совпадают побайтово между MISS
// и HIT (ObjectMeta переживает круг через каталог); Content-Encoding
// в ответе нет — upstream получил явный Accept-Encoding: identity
// (комплаентный upstream не жмёт), а кеш не декларирует кодировку,
// которой не несёт.
func TestProxyHitHeadersIdentityEncoding(t *testing.T) {
	body := []byte("HEADER-CONTRACT-64-bytes-padding-padding-padding-padding!!")
	var sawAcceptEncoding atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAcceptEncoding.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "application/x-contract")
		w.Header().Set("ETag", `"hdr-v1"`)
		_, _ = w.Write(body)
	}))
	t.Cleanup(up.Close)

	storage := testutil.NewFakeStorage(testutil.NewManualClock(aptTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(aptTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 7, Name: "debian", Ecosystem: "apt",
		BaseURL: up.URL + "/debian", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := apt.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"apt": adapter},
	})
	const path = "/apt/debian/headers/obj.bin"
	wantSHA := sha256Hex(body)

	rec := aptGet(t, h, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("первый запрос: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("первый X-Cache = %q, хочу MISS", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantSHA {
		t.Fatalf("первый sha256 = %s, хочу %s", got, wantSHA)
	}
	if got := sawAcceptEncoding.Load(); got != "identity" {
		t.Errorf("upstream видел Accept-Encoding = %q, хочу identity", got)
	}
	missHeaders := map[string]string{
		"Content-Type":   rec.Header().Get("Content-Type"),
		"Content-Length": rec.Header().Get("Content-Length"),
		"ETag":           rec.Header().Get("ETag"),
	}
	if missHeaders["Content-Type"] != "application/x-contract" {
		t.Errorf("MISS Content-Type = %q", missHeaders["Content-Type"])
	}
	if missHeaders["Content-Length"] != strconv.Itoa(len(body)) {
		t.Errorf("MISS Content-Length = %q, хочу %d", missHeaders["Content-Length"], len(body))
	}
	if missHeaders["ETag"] != `"hdr-v1"` {
		t.Errorf("MISS ETag = %q", missHeaders["ETag"])
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("MISS Content-Encoding = %q, хочу пусто", got)
	}

	rec = aptGet(t, h, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("второй запрос: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("второй X-Cache = %q, хочу HIT", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantSHA {
		t.Fatalf("второй sha256 = %s, хочу %s", got, wantSHA)
	}
	for name, miss := range missHeaders {
		if got := rec.Header().Get(name); got != miss {
			t.Errorf("HIT %s = %q, MISS дал %q (заголовки не совпали побайтово)", name, got, miss)
		}
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("HIT Content-Encoding = %q, хочу пусто", got)
	}
}
