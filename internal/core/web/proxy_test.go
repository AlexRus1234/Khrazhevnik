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

package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// newProxyEnv — публичный роутер с живым движком кеша над
// httptest-upstream.
func newProxyEnv(t *testing.T, h http.HandlerFunc) (http.Handler, *testutil.ManualClock, *metrics.Cache, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	m := metrics.NewCache()
	engine := cacheengine.New(
		testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(),
		up.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		m,
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: 40 * time.Second}
	handler := BuildPublicRouter(Deps{Version: "test", Cache: engine, Ecosystems: map[string]port.Ecosystem{"t": eco}})
	return handler, clock, m, up
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestProxyUnknownEcosystem(t *testing.T) {
	h, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	if rec := get(t, h, "/nosuch/pkg/a.deb"); rec.Code != http.StatusNotFound {
		t.Fatalf("неизвестная экосистема = %d, хочу 404", rec.Code)
	}
}

func TestProxyServesAndCaches(t *testing.T) {
	h, _, m, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/deb")
		w.Header().Set("ETag", `"e1"`)
		_, _ = io.WriteString(w, "payload")
	})

	rec := get(t, h, "/t/pkg/a.deb")
	if rec.Code != http.StatusOK {
		t.Fatalf("первый ответ = %d, тело %q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "payload" {
		t.Fatalf("тело = %q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache первого = %q, хочу MISS", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/deb" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("ETag"); got != `"e1"` {
		t.Errorf("ETag = %q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "7" {
		t.Errorf("Content-Length = %q, хочу 7", got)
	}

	rec = get(t, h, "/t/pkg/a.deb")
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache второго = %q, хочу HIT", got)
	}
	if got := m.BytesToClients.Load(); got != 14 {
		t.Errorf("bytes_to_clients = %d, хочу 14 (7+7)", got)
	}
}

func TestProxyErrorCodes(t *testing.T) {
	t.Run("404 upstream → 404 клиенту", func(t *testing.T) {
		h, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
		rec := get(t, h, "/t/pkg/none.deb")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("код = %d, хочу 404", rec.Code)
		}
		if got := rec.Header().Get("X-Cache"); got != "" {
			t.Errorf("X-Cache на ошибке = %q, хочу пусто", got)
		}
	})
	t.Run("5xx без копии → 502 клиенту", func(t *testing.T) {
		h, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
		if rec := get(t, h, "/t/idx/down"); rec.Code != http.StatusBadGateway {
			t.Fatalf("код = %d, хочу 502", rec.Code)
		}
	})
	t.Run("too large → 502 клиенту", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = io.WriteString(w, "x")
		}))
		t.Cleanup(up.Close)
		clock := testutil.NewManualClock(time.Unix(0, 0))
		engine := cacheengine.New(testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(), up.Client(), clock, cacheengine.Config{MaxObjectSize: 10}, nil)
		eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL}
		h := BuildPublicRouter(Deps{Cache: engine, Ecosystems: map[string]port.Ecosystem{"t": eco}})
		if rec := get(t, h, "/t/pkg/big.deb"); rec.Code != http.StatusBadGateway {
			t.Fatalf("код = %d, хочу 502", rec.Code)
		}
	})
}

func TestProxyStaleServedWithWarning(t *testing.T) {
	requests := 0
	h, clock, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("ETag", `"v1"`)
			_, _ = io.WriteString(w, "fresh")
			return
		}
		w.WriteHeader(500)
	})

	rec := get(t, h, "/t/idx/idx")
	if rec.Code != http.StatusOK {
		t.Fatalf("прогрев = %d", rec.Code)
	}
	clock.Advance(41 * time.Second)

	rec = get(t, h, "/t/idx/idx")
	if rec.Code != http.StatusOK {
		t.Fatalf("stale-ответ = %d, хочу 200", rec.Code)
	}
	if rec.Body.String() != "fresh" {
		t.Fatalf("тело stale = %q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "STALE" {
		t.Errorf("X-Cache = %q, хочу STALE", got)
	}
	if got := rec.Header().Get("Warning"); got != `111 khrazhevnik "revalidation failed"` {
		t.Errorf("Warning = %q", got)
	}
}
