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

// E2E rpm-md-прокси: httptest-upstream с мини-rpm-репозиторием
// (repomd.xml + primary с хешем в имени + один .rpm) → наш прокси →
// метаданные byte-exact (sha256 совпадает с upstream), .rpm из кеша
// (upstream-счётчик пакета = 1 после двух запросов). Сессия 08.
//
// dnf-совместимость проверяется руками (шаги — в коммите сессии 08):
//
//	khrazhevnik -add-remote rpm-md/fedora=https://mirrors.fedoraproject.org/fedora/releases/40/Everything/x86_64/os
//	dnf --repofrompath=test,http://localhost:29202/rpm/fedora makecache
//	dnf --repo=test --refresh list available

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
	"khrazhevnik/internal/mod/ecosystem/rpmmmd"
	"khrazhevnik/internal/testutil"
)

// rpmUpstream — httptest-сервер с мини-rpm-репо: repomd.xml, primary с
// хешем в имени и один .rpm. Считает запросы по пути (для проверки кеша).
type rpmUpstream struct {
	mu       atomic.Int64
	rpmBytes []byte
	repomd   []byte
	primary  []byte
	srv      *httptest.Server
}

// hashHex — хеш в имени primary (content-addressed: immutable).
const rpmPrimaryHash = "0458a2b3c4d5e6f7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"

func newRpmUpstream(t *testing.T) *rpmUpstream {
	t.Helper()
	u := &rpmUpstream{
		rpmBytes: []byte("RPM-CONTENT-100-bytes-padding-padding-padding-padding-padding!!"),
		repomd: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>2026-08-22T12:00:00Z</revision>
  <data type="primary">
    <checksum type="sha256">` + rpmPrimaryHash + `</checksum>
    <location href="repodata/` + rpmPrimaryHash + `-primary.xml.gz"/>
    <timestamp>1724323200</timestamp>
    <size>123</size>
  </data>
</repomd>
`),
		primary: []byte("<primary/>"),
	}
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *rpmUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Add(1)
	switch r.URL.Path {
	case "/fedora/repodata/repomd.xml":
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("ETag", `"repomd-v1"`)
		_, _ = w.Write(u.repomd)
	case "/fedora/repodata/" + rpmPrimaryHash + "-primary.xml.gz":
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(u.primary)
	case "/fedora/Packages/f/foo-1.0-1.x86_64.rpm":
		w.Header().Set("Content-Type", "application/x-rpm")
		_, _ = w.Write(u.rpmBytes)
	default:
		http.NotFound(w, r)
	}
}

func (u *rpmUpstream) hits() int64 { return u.mu.Load() }

// rpmTestStart — детерминированный момент для движка кеша и адаптера.
var rpmTestStart = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func TestRpmMdProxyByteExactAndCache(t *testing.T) {
	up := newRpmUpstream(t)
	storage := testutil.NewFakeStorage(testutil.NewManualClock(rpmTestStart))
	index := testutil.NewFakeObjectIndex()
	clock := testutil.NewManualClock(rpmTestStart)
	remotes := testutil.NewFakeRemoteStore()
	if _, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 9, Name: "fedora", Ecosystem: "rpm-md",
		BaseURL: up.srv.URL + "/fedora", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := rpmmmd.New(remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cacheengine.New(storage, index, up.srv.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := web.BuildPublicRouter(web.Deps{
		Log: log, Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"rpm-md": adapter},
	})

	// Метаданные (mutable): byte-exact c upstream, sha256 совпадает.
	repomdSHA := sha256.Sum256(up.repomd)
	wantRepomdHex := hex.EncodeToString(repomdSHA[:])
	rec := rpmGet(t, h, "/rpm/fedora/repodata/repomd.xml")
	if rec.Code != http.StatusOK {
		t.Fatalf("repomd: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantRepomdHex {
		t.Fatalf("repomd sha256 = %s, хочу %s (byte-exact нарушен)", got, wantRepomdHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("repomd первый X-Cache = %q, хочу MISS", got)
	}

	// primary с хешем в имени — immutable (content-addressed), но первый
	// запрос — upstream-промах. Второй — HIT из кеша.
	primarySHA := sha256.Sum256(up.primary)
	wantPrimaryHex := hex.EncodeToString(primarySHA[:])
	primaryPath := "/rpm/fedora/repodata/" + rpmPrimaryHash + "-primary.xml.gz"
	rec = rpmGet(t, h, primaryPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("primary первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantPrimaryHex {
		t.Fatalf("primary sha256 = %s, хочу %s (byte-exact нарушен)", got, wantPrimaryHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("primary первый X-Cache = %q, хочу MISS", got)
	}
	upstreamHitsAfterPrimary := up.hits()

	// второй запрос primary — из кеша, upstream не дёргается
	rec = rpmGet(t, h, primaryPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("primary второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("primary второй X-Cache = %q, хочу HIT", got)
	}
	if up.hits() != upstreamHitsAfterPrimary {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (primary не из кеша)", up.hits(), upstreamHitsAfterPrimary)
	}

	// Пакет (immutable): первый запрос — upstream-промах, второй — HIT.
	rpmSHA := sha256.Sum256(up.rpmBytes)
	wantRpmHex := hex.EncodeToString(rpmSHA[:])
	rec = rpmGet(t, h, "/rpm/fedora/Packages/f/foo-1.0-1.x86_64.rpm")
	if rec.Code != http.StatusOK {
		t.Fatalf(".rpm первый: код %d", rec.Code)
	}
	if got := sha256Hex(rec.Body.Bytes()); got != wantRpmHex {
		t.Fatalf(".rpm sha256 = %s, хочу %s (byte-exact нарушен)", got, wantRpmHex)
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf(".rpm первый X-Cache = %q, хочу MISS", got)
	}
	upstreamHitsAfterRpm := up.hits()

	// второй запрос пакета — из кеша, upstream не дёргается
	rec = rpmGet(t, h, "/rpm/fedora/Packages/f/foo-1.0-1.x86_64.rpm")
	if rec.Code != http.StatusOK {
		t.Fatalf(".rpm второй: код %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf(".rpm второй X-Cache = %q, хочу HIT", got)
	}
	if up.hits() != upstreamHitsAfterRpm {
		t.Errorf("upstream получил %d запросов после HIT, хочу %d (пакет не из кеша)", up.hits(), upstreamHitsAfterRpm)
	}
}

// rpmGet — GET к публичному роутеру.
func rpmGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
