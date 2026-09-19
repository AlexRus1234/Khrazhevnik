// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; even without the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build integration

// E2E xbps-прокси (Void Linux): httptest-upstream с мини-репо
// (zstd+tar `<arch>-repodata`, пакет `Mustache`, legacy-подпись
// `.xbps.sig2`) → наш прокси → раздача byte-exact, повтор — X-Cache:
// HIT, mutable repodata ревалидируется по If-Modified-Since (upstream
// отвечает 304 без тела, клиент получает копию из кеша), отсутствующий
// объект — 404 с negative-кешем. Сессия 130.
//
// xbps-совместимость проверяется руками (шаги — в коммите сессии 144):
//
//	khrazhevnik -add-remote xbps/void=https://repo-default.voidlinux.org/current
//	# /etc/xbps.d/00-repository-main.conf:
//	# repository=http://localhost:29202/xbps/void
//	xbps-install -Syu

package integration

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/xbps"
	"khrazhevnik/internal/testutil"
)

// repoDataPkg — запись index.plist: имя пакета и поля, по которым
// клиент сам строит имя файла пакета (pkgver/architecture) и проверяет
// тело (filename-sha256/filename-size). Тип продублирован тест-пакетом
// парсера (сессия 131) — правило «тесты самодостаточны».
type repoDataPkg struct {
	Name   string
	Pkgver string
	Arch   string
	SHA256 string
	Size   int
}

// xbpsUpstream — httptest-сервер с мини-Void-репо: mutable
// `/x86_64-repodata` (zstd+tar), immutable пакет `Mustache` и его
// `.sig2`. Считает запросы всего/repodata/conditional (If-Modified-Since)
// и отданные 304 — счётчики фикстуры.
type xbpsUpstream struct {
	hits         atomic.Int64
	repodataHits atomic.Int64
	condRequests atomic.Int64
	notModified  atomic.Int64
	repodata     []byte
	repodataMod  time.Time
	pkg          []byte
	sig          []byte
	srv          *httptest.Server
}

func newXbpsUpstream(t *testing.T) *xbpsUpstream {
	t.Helper()
	pkg := []byte("XBPS-PKG-Mustache-4.1_1-100-bytes-padding-padding-padding-padding!!")
	sig := bytes.Repeat([]byte{0xA5}, 512)
	u := &xbpsUpstream{
		pkg:         pkg,
		sig:         sig,
		repodataMod: time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC),
	}
	// Реальные имена из Void: регистр значим (Mustache, libstdc++).
	u.repodata = buildTestRepoData(t, []repoDataPkg{
		{Name: "Mustache", Pkgver: "4.1_1", Arch: "x86_64", SHA256: sha256Hex(pkg), Size: len(pkg)},
		{Name: "libstdc++", Pkgver: "13.2.0_1", Arch: "x86_64", SHA256: sha256Hex(sig), Size: len(sig)},
		{Name: "python3-cairo", Pkgver: "1.26.0_1", Arch: "noarch", SHA256: sha256Hex([]byte("noarch-payload")), Size: 64},
	})
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

// serve отдаёт repodata безусловно и 304 на условный запрос (без тела):
// libfetch шлёт If-Modified-Since, ревалидацию выполняет движок кеша.
func (u *xbpsUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	switch r.URL.Path {
	case "/x86_64-repodata":
		u.repodataHits.Add(1)
		w.Header().Set("Content-Type", "application/zstd")
		w.Header().Set("Last-Modified", u.repodataMod.UTC().Format(http.TimeFormat))
		if r.Header.Get("If-Modified-Since") != "" {
			u.condRequests.Add(1)
			u.notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(u.repodata)
	case "/Mustache-4.1_1.x86_64.xbps":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.pkg)
	case "/libstdc++-13.2.0_1.x86_64.xbps.sig2":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.sig)
	default:
		http.NotFound(w, r)
	}
}

// buildTestRepoData собирает `<arch>-repodata`: pax-tar с index.plist
// (XML-plist-словарь пакетов), заглушкой index-meta.plist и пустым
// stage.plist, сжатый zstd level 9. Порядок записей — index.plist
// первой (парсер рассчитывает на неё).
func buildTestRepoData(t *testing.T, packages []repoDataPkg) []byte {
	t.Helper()
	var index strings.Builder
	index.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	index.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	index.WriteString("<plist version=\"1.0\">\n<dict>\n")
	for _, p := range packages {
		fmt.Fprintf(&index, "\t<key>%s</key>\n\t<dict>\n", p.Name)
		fmt.Fprintf(&index, "\t\t<key>pkgver</key>\n\t\t<string>%s</string>\n", p.Pkgver)
		fmt.Fprintf(&index, "\t\t<key>architecture</key>\n\t\t<string>%s</string>\n", p.Arch)
		fmt.Fprintf(&index, "\t\t<key>filename-sha256</key>\n\t\t<string>%s</string>\n", p.SHA256)
		fmt.Fprintf(&index, "\t\t<key>filename-size</key>\n\t\t<integer>%d</integer>\n", p.Size)
		index.WriteString("\t</dict>\n")
	}
	index.WriteString("</dict>\n</plist>\n")

	meta := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\">\n<dict>\n\t<key>public-key</key>\n\t<data>AAAA</data>\n</dict>\n</plist>\n"

	entries := []struct {
		name string
		data []byte
	}{
		{"index.plist", []byte(index.String())},
		{"index-meta.plist", []byte(meta)},
		{"stage.plist", nil},
	}
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644,
			Size: int64(len(e.data)), Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zstBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zstBuf, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zstBuf.Bytes()
}

// xbpsTestStart — детерминированный момент для движка кеша и адаптера.
var xbpsTestStart = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func TestXbpsProxyByteExactAndCache(t *testing.T) {
	up := newXbpsUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(xbpsTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(xbpsTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 130, Name: "void", Ecosystem: "xbps",
		BaseURL: up.srv.URL, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := xbps.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"xbps": adapter},
	})

	// Repodata (mutable): первый — MISS, байты совпадают с upstream.
	const repodataPath = "/xbps/void/x86_64-repodata"
	wantRepodata := sha256Hex(up.repodata)
	rec := xbpsGet(t, h, repodataPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("repodata: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantRepodata {
		t.Fatalf("repodata sha256 = %s, хочу %s (byte-exact нарушен)", got, wantRepodata)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("repodata первый X-Cache = %q, хочу MISS", got)
	}
	lastMod := rec.Header().Get("Last-Modified")
	if lastMod == "" {
		t.Fatal("repodata без Last-Modified: нечего слать в If-Modified-Since")
	}

	// Повторный GET — из кеша, upstream не дёргается.
	repodataHits := up.repodataHits.Load()
	rec = xbpsGet(t, h, repodataPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("repodata второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("repodata второй X-Cache = %q, хочу HIT", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantRepodata {
		t.Fatalf("repodata второй sha256 = %s, хочу %s", got, wantRepodata)
	}
	if up.repodataHits.Load() != repodataHits {
		t.Errorf("upstream получил %d запросов repodata после HIT, хочу %d", up.repodataHits.Load(), repodataHits)
	}

	// Пакет (immutable): byte-exact, регистр имени сохранён в StorageKey.
	const pkgPath = "/xbps/void/Mustache-4.1_1.x86_64.xbps"
	wantPkg := sha256Hex(up.pkg)
	rec = xbpsGet(t, h, pkgPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("пакет первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPkg {
		t.Fatalf("пакет sha256 = %s, хочу %s (byte-exact нарушен)", got, wantPkg)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("пакет первый X-Cache = %q, хочу MISS", got)
	}
	if _, err := storage.Stat(t.Context(), "cache/xbps/130/Mustache-4.1_1.x86_64.xbps"); err != nil {
		t.Errorf("ключ кеша с регистром Mustache отсутствует: %v", err)
	}
	if _, err := storage.Stat(t.Context(), "cache/xbps/130/mustache-4.1_1.x86_64.xbps"); err == nil {
		t.Errorf("ключ кеша лоуэркейснут — регистрочувствительность Void потеряна")
	}

	pkgHits := up.hits.Load()
	rec = xbpsGet(t, h, pkgPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("пакет второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("пакет второй X-Cache = %q, хочу HIT", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPkg {
		t.Fatalf("пакет второй sha256 = %s, хочу %s", got, wantPkg)
	}
	if up.hits.Load() != pkgHits {
		t.Errorf("upstream получил %d запросов после HIT пакета, хочу %d (пакет не из кеша)", up.hits.Load(), pkgHits)
	}

	// Legacy-подпись (immutable): byte-exact и кеш.
	const sigPath = "/xbps/void/libstdc++-13.2.0_1.x86_64.xbps.sig2"
	wantSig := sha256Hex(up.sig)
	rec = xbpsGet(t, h, sigPath)
	if rec.Code != http.StatusOK {
		t.Fatalf(".sig2 первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantSig {
		t.Fatalf(".sig2 sha256 = %s, хочу %s (byte-exact нарушен)", got, wantSig)
	}
	sigHits := up.hits.Load()
	rec = xbpsGet(t, h, sigPath)
	if rec.Code != http.StatusOK {
		t.Fatalf(".sig2 второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf(".sig2 второй X-Cache = %q, хочу HIT", got)
	}
	if up.hits.Load() != sigHits {
		t.Errorf("upstream получил %d запросов после HIT .sig2, хочу %d", up.hits.Load(), sigHits)
	}

	// Отсутствующий объект: 404, повтор — 404 из negative-кеша
	// (upstream дергается один раз).
	const missPath = "/xbps/void/nope-1.0_1.x86_64.xbps"
	rec = xbpsGet(t, h, missPath)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("отсутствующий: код %d, хочу 404", rec.Code)
	}
	missHits := up.hits.Load()
	rec = xbpsGet(t, h, missPath)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("отсутствующий повтор: код %d, хочу 404", rec.Code)
	}
	if up.hits.Load() != missHits {
		t.Errorf("upstream получил %d запросов после negative-кеша, хочу %d", up.hits.Load(), missHits)
	}

	// Ревалидация mutable repodata: TTL индекса xbps — 5m, после него
	// движок шлёт upstream If-Modified-Since (из первого ответа),
	// upstream отвечает 304 без тела, клиент получает копию из кеша.
	clock.Advance(6 * time.Minute)
	req := httptest.NewRequest(http.MethodGet, repodataPath, nil)
	req.Header.Set("If-Modified-Since", lastMod)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ревалидация repodata: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("ревалидация repodata X-Cache = %q, хочу HIT", got)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantRepodata {
		t.Fatalf("ревалидация repodata sha256 = %s, хочу %s", got, wantRepodata)
	}
	if up.condRequests.Load() != 1 {
		t.Errorf("upstream получил %d условных запросов, хочу 1", up.condRequests.Load())
	}
	if up.notModified.Load() != 1 {
		t.Errorf("upstream отдал %d ответов 304, хочу 1", up.notModified.Load())
	}
}

// xbpsGet — GET к публичному роутеру.
func xbpsGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
