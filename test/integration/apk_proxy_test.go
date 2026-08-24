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

// E2E apk-прокси: httptest-upstream с мини-репозиторием Alpine
// (APKINDEX.tar.gz [gzip+tar] + 2 .apk) → наш прокси → метаданные
// byte-exact (sha256 совпадает с upstream), .apk из кеша (upstream-счётчик
// пакета = 1 после двух запросов). Сессия 12.
//
// apk-совместимость проверяется руками (шаги — в коммите сессии 12):
//
//	khrazhevnik -add-remote apk/alpine=https://dl-cdn.alpinelinux.org/alpine
//	# /etc/apk/repositories:
//	# http://localhost:29202/apk/alpine/v3.20/main
//	apk update

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/apk"
	"khrazhevnik/internal/testutil"
)

// apkUpstream — httptest-сервер с мини-Alpine-репо: APKINDEX.tar.gz
// (gzip+tar с APKINDEX-текстом) + 2 .apk. Считает запросы по пути.
type apkUpstream struct {
	mu        atomic.Int64
	apk1      []byte
	apk2      []byte
	apkIndex  []byte
	srv       *httptest.Server
}

func newApkUpstream(t *testing.T) *apkUpstream {
	t.Helper()
	u := &apkUpstream{
		apk1: []byte("APK-PKG-1-100-bytes-padding-padding-padding-padding-padding!!"),
		apk2: []byte("APK-PKG-2-100-bytes-padding-padding-padding-padding-padding!!"),
	}
	// APKINDEX: текстовый формат «K:V», упакованный в gzip+tar.
	indexText := []byte("P:apk-example\nV:1.0-r0\nF:x86_64/apk-example-1.0-r0.apk\n\n" +
		"P:second-pkg\nV:2.0-r1\nF:x86_64/second-pkg-2.0-r1.apk\n\n")
	u.apkIndex = newApkIndex(t, indexText)
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *apkUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Add(1)
	switch r.URL.Path {
	case "/alpine/v3.20/main/x86_64/APKINDEX.tar.gz":
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("ETag", `"apkindex-v1"`)
		_, _ = w.Write(u.apkIndex)
	case "/alpine/v3.20/main/x86_64/apk-example-1.0-r0.apk":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.apk1)
	case "/alpine/v3.20/main/x86_64/second-pkg-2.0-r1.apk":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.apk2)
	default:
		http.NotFound(w, r)
	}
}

func (u *apkUpstream) hits() int64 { return u.mu.Load() }

// newApkIndex упаковывает APKINDEX-текст в gzip+tar (формат apk).
func newApkIndex(t *testing.T, indexText []byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "APKINDEX", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(indexText)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(indexText); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzBuf.Bytes()
}

var apkTestStart = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func TestApkProxyByteExactAndCache(t *testing.T) {
	up := newApkUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(apkTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(apkTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 13, Name: "alpine", Ecosystem: "apk",
		BaseURL: up.srv.URL + "/alpine", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := apk.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"apk": adapter},
	})

	// Метаданные (mutable): byte-exact c upstream, sha256 совпадает.
	idxSHA := sha256.Sum256(up.apkIndex)
	wantIdxHex := hex.EncodeToString(idxSHA[:])
	rec := apkGet(t, h, "/apk/alpine/v3.20/main/x86_64/APKINDEX.tar.gz")
	if rec.Code != http.StatusOK {
		t.Fatalf("APKINDEX: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantIdxHex {
		t.Fatalf("APKINDEX sha256 = %s, хочу %s (byte-exact нарушен)", got, wantIdxHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("APKINDEX первый X-Cache = %q, хочу MISS", got)
	}

	// Пакет 1 (immutable): первый запрос — upstream-промах, второй — HIT.
	apk1SHA := sha256.Sum256(up.apk1)
	wantApk1Hex := hex.EncodeToString(apk1SHA[:])
	rec = apkGet(t, h, "/apk/alpine/v3.20/main/x86_64/apk-example-1.0-r0.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf(".apk первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantApk1Hex {
		t.Fatalf(".apk sha256 = %s, хочу %s (byte-exact нарушен)", got, wantApk1Hex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf(".apk первый X-Cache = %q, хочу MISS", got)
	}
	hitsAfterFirst := up.hits()

	// второй запрос пакета — из кеша, upstream не дёргается
	rec = apkGet(t, h, "/apk/alpine/v3.20/main/x86_64/apk-example-1.0-r0.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf(".apk второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf(".apk второй X-Cache = %q, хочу HIT", got)
	}
	if up.hits() != hitsAfterFirst {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (пакет не из кеша)", up.hits(), hitsAfterFirst)
	}

	// Пакет 2 (immutable): другой пакет — тоже immutable, первый MISS.
	apk2SHA := sha256.Sum256(up.apk2)
	wantApk2Hex := hex.EncodeToString(apk2SHA[:])
	rec = apkGet(t, h, "/apk/alpine/v3.20/main/x86_64/second-pkg-2.0-r1.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf(".apk второй пакет: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantApk2Hex {
		t.Fatalf(".apk второй пакет sha256 = %s, хочу %s (byte-exact нарушен)", got, wantApk2Hex)
	}
}

func apkGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
