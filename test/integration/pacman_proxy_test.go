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

// E2E pacman-прокси: httptest-upstream с мини-репозиторием Arch
// (core.db [zstd-tar] + 2 .pkg.tar.zst) → наш прокси → метаданные
// byte-exact (sha256 совпадает с upstream), .pkg из кеша (upstream-счётчик
// пакета = 1 после двух запросов). Сессия 12.
//
// pacman-совместимость проверяется руками (шаги — в коммите сессии 12):
//
//	khrazhevnik -add-remote pacman/arch=https://mirror.example.com/archlinux
//	# /etc/pacman.conf:
//	# [core]
//	# Server = http://localhost:29202/pacman/arch/$repo/os/$arch
//	pacman -Syu

package integration

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/pacman"
	"khrazhevnik/internal/testutil"
)

// pacmanUpstream — httptest-сервер с мини-Arch-репо: core.db
// (zstd-сжатый tar с 2 desc) + 2 .pkg.tar.zst. Считает запросы по пути.
type pacmanUpstream struct {
	mu     atomic.Int64
	pkg1   []byte
	pkg2   []byte
	coreDB []byte
	srv    *httptest.Server
}

func newPacmanUpstream(t *testing.T) *pacmanUpstream {
	t.Helper()
	u := &pacmanUpstream{
		pkg1: []byte("PACMAN-PKG-1-100-bytes-padding-padding-padding-padding-padding!!"),
		pkg2: []byte("PACMAN-PKG-2-100-bytes-padding-padding-padding-padding-padding!!"),
	}
	// core.db: zstd-сжатый tar с двумя desc-файлами.
	desc1 := []byte("%FILENAME%\npacman-example-1.0-1-x86_64.pkg.tar.zst\n%NAME%\npacman-example\n%VERSION%\n1.0-1\n")
	desc2 := []byte("%FILENAME%\nsecond-pkg-2.0-1-any.pkg.tar.xz\n%NAME%\nsecond-pkg\n%VERSION%\n2.0-1\n")
	u.coreDB = newPacmanDB(t, map[string][]byte{
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	})
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *pacmanUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Add(1)
	switch r.URL.Path {
	case "/archlinux/core/os/x86_64/core.db":
		w.Header().Set("Content-Type", "application/zstd")
		w.Header().Set("ETag", `"coredb-v1"`)
		_, _ = w.Write(u.coreDB)
	case "/archlinux/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.pkg1)
	case "/archlinux/core/os/x86_64/second-pkg-2.0-1-any.pkg.tar.xz":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.pkg2)
	default:
		http.NotFound(w, r)
	}
}

func (u *pacmanUpstream) hits() int64 { return u.mu.Load() }

// newPacmanDB собирает zstd-сжатый tar из map «путь → байты».
func newPacmanDB(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zstBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zstBuf)
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

var pacmanTestStart = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func TestPacmanProxyByteExactAndCache(t *testing.T) {
	up := newPacmanUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(pacmanTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(pacmanTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 11, Name: "arch", Ecosystem: "pacman",
		BaseURL: up.srv.URL + "/archlinux", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := pacman.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"pacman": adapter},
	})

	// Метаданные (mutable): byte-exact c upstream, sha256 совпадает.
	dbSHA := sha256.Sum256(up.coreDB)
	wantDBHex := hex.EncodeToString(dbSHA[:])
	rec := pacmanGet(t, h, "/pacman/arch/core/os/x86_64/core.db")
	if rec.Code != http.StatusOK {
		t.Fatalf("core.db: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantDBHex {
		t.Fatalf("core.db sha256 = %s, хочу %s (byte-exact нарушен)", got, wantDBHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("core.db первый X-Cache = %q, хочу MISS", got)
	}

	// Пакет 1 (immutable): первый запрос — upstream-промах, второй — HIT.
	pkg1SHA := sha256.Sum256(up.pkg1)
	wantPkg1Hex := hex.EncodeToString(pkg1SHA[:])
	rec = pacmanGet(t, h, "/pacman/arch/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst")
	if rec.Code != http.StatusOK {
		t.Fatalf(".pkg.tar.zst первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPkg1Hex {
		t.Fatalf(".pkg.tar.zst sha256 = %s, хочу %s (byte-exact нарушен)", got, wantPkg1Hex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf(".pkg.tar.zst первый X-Cache = %q, хочу MISS", got)
	}
	hitsAfterFirst := up.hits()

	// второй запрос пакета — из кеша, upstream не дёргается
	rec = pacmanGet(t, h, "/pacman/arch/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst")
	if rec.Code != http.StatusOK {
		t.Fatalf(".pkg.tar.zst второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf(".pkg.tar.zst второй X-Cache = %q, хочу HIT", got)
	}
	if up.hits() != hitsAfterFirst {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (пакет не из кеша)", up.hits(), hitsAfterFirst)
	}

	// Пакет 2 (immutable): другой формат сжатия (.tar.xz) — тоже immutable.
	pkg2SHA := sha256.Sum256(up.pkg2)
	wantPkg2Hex := hex.EncodeToString(pkg2SHA[:])
	rec = pacmanGet(t, h, "/pacman/arch/core/os/x86_64/second-pkg-2.0-1-any.pkg.tar.xz")
	if rec.Code != http.StatusOK {
		t.Fatalf(".pkg.tar.xz первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPkg2Hex {
		t.Fatalf(".pkg.tar.xz sha256 = %s, хочу %s (byte-exact нарушен)", got, wantPkg2Hex)
	}
}

func pacmanGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
