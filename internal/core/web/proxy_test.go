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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// newProxyEnv — публичный роутер с живым движком кеша над
// httptest-upstream. Возвращает и Metrics-экспортер (завёрнут в Deps)
// для smoke-проверок exposition-текста.
func newProxyEnv(t *testing.T, h http.HandlerFunc) (http.Handler, *testutil.ManualClock, *metrics.Cache, *metrics.Handler, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	m := metrics.NewCache()
	exporter := metrics.NewHandler(m, prometheus.NewRegistry())
	engine := cacheengine.New(
		testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(),
		up.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		m,
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: 40 * time.Second}
	handler := BuildPublicRouter(Deps{Version: "test", Cache: engine, Ecosystems: map[string]port.Ecosystem{"t": eco}, Metrics: exporter})
	return handler, clock, m, exporter, up
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// unavailableStorage — фейк storage с отказом чтения/записи: имитация
// ENOSPC/EIO-класса сбоя адаптера (сессия 50) без FS-семантики носителя.
type unavailableStorage struct {
	*testutil.FakeStorage
}

func unavailable() error {
	return &domain.UnavailableError{What: "хранилище", Reason: "сбой носителя"}
}

func (unavailableStorage) Get(context.Context, string) (port.Object, error) {
	return port.Object{}, unavailable()
}

func (unavailableStorage) Stat(context.Context, string) (port.Meta, error) {
	return port.Meta{}, unavailable()
}

func (unavailableStorage) Put(context.Context, string) (port.Writer, error) {
	return nil, unavailable()
}

// writeFailStorage — хранилище с живым чтением и отказом записи:
// классифицированный UnavailableError (что теперь отдают fs/s3-адаптеры
// на сбое носителя, сессия 60).
type writeFailStorage struct {
	*testutil.FakeStorage
}

func (writeFailStorage) Put(context.Context, string) (port.Writer, error) {
	return nil, unavailable()
}

func TestProxyUnknownEcosystem(t *testing.T) {
	h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	if rec := get(t, h, "/nosuch/pkg/a.deb"); rec.Code != http.StatusNotFound {
		t.Fatalf("неизвестная экосистема = %d, хочу 404", rec.Code)
	}
}

func TestProxyServesAndCaches(t *testing.T) {
	h, _, m, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
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
	// Upstream-тип «application/deb» не проходит: .deb — пакетное
	// расширение, ответ маппится allowlist'ом (сессия 78). Тело и
	// остальные заголовки — byte-exact как прежде.
	if got := rec.Header().Get("Content-Type"); got != "application/vnd.debian.binary-package" {
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

// TestProxyPercentEscapedPlus — apt шлёт «+» в пути как %2b (CI-факт
// №4): chi v5.3.1 маршрутизирует по RawPath, wildcard приходит
// экранированным, и ключ с «%» отсекался whitelist'ом ValidateKey →
// 400 на валидном upstream-пути. Декод до ValidateKey: %2b-написание
// даёт тот же объект кеша, что и сырое «+».
func TestProxyPercentEscapedPlus(t *testing.T) {
	hits := 0
	h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pkg/a+bb.deb" {
			hits++
		}
		_, _ = io.WriteString(w, "payload")
	})

	// Экранированное написание (как на проводе от apt): 200 + payload.
	// %2b → «+», хвост «bb.deb» литеральный — то же имя, что у upstream.
	rec := get(t, h, "/t/pkg/a%2bbb.deb")
	if rec.Code != http.StatusOK {
		t.Fatalf("%%2b-запрос = %d, тело %q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "payload" {
		t.Fatalf("тело = %q, хочу payload", rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache %%2b-запроса = %q, хочу MISS", got)
	}

	// Сырое «+» — тот же объект кеша: HIT, upstream не дёргается
	// (один объект на оба написания).
	rec = get(t, h, "/t/pkg/a+bb.deb")
	if rec.Code != http.StatusOK {
		t.Fatalf("raw-запрос = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache raw-запроса = %q, хочу HIT", got)
	}
	if hits != 1 {
		t.Errorf("upstream получил %d запросов, хочу 1 (один объект на оба написания)", hits)
	}

	// Двойное кодирование: %252b декодится в «%2b» с «%» — whitelist
	// ValidateKey режет fail-closed → 400.
	rec = get(t, h, "/t/pkg/a%252b.deb")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("%%252b-запрос = %d, хочу 400 (тело %q)", rec.Code, rec.Body.String())
	}

	// Битый escape (RawPath руками, in-memory): декод падает до
	// движка → 400, не 500, и upstream не дёргается вовсе.
	hitsBefore := hits
	req := httptest.NewRequest(http.MethodGet, "/t/pkg/a.deb", nil)
	req.URL.RawPath = "/t/pkg/a%zz.deb"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("битый escape = %d, хочу 400 (тело %q)", rec2.Code, rec2.Body.String())
	}
	if hits != hitsBefore {
		t.Errorf("битый escape дёрнул upstream (%d → %d), хочу без похода", hitsBefore, hits)
	}
}

func TestProxyErrorCodes(t *testing.T) {
	t.Run("404 upstream → 404 клиенту", func(t *testing.T) {
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
		rec := get(t, h, "/t/pkg/none.deb")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("код = %d, хочу 404", rec.Code)
		}
		if got := rec.Header().Get("X-Cache"); got != "" {
			t.Errorf("X-Cache на ошибке = %q, хочу пусто", got)
		}
	})
	t.Run("5xx без копии → 502 клиенту", func(t *testing.T) {
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
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
	t.Run("storage unavailable → 503, не 502", func(t *testing.T) {
		// Сбой нашего storage/каталога — не вина upstream: 503, как в
		// auth-слое (аудит 2026-08-30, сессия 45). Маппинг проверяем
		// напрямую: в live-прогоне источник ошибки — адаптер хранилища.
		rec := httptest.NewRecorder()
		writeProxyError(rec, &domain.UnavailableError{What: "хранилище", Reason: "сбой"})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("код = %d, хочу 503", rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "unavailable") {
			t.Errorf("тело = %q, хочу текст storage unavailable", body)
		}
	})
	t.Run("сбой storage при отдаче → 503 сквозь движок", func(t *testing.T) {
		// Полный путь (сессия 50): UnavailableError от адаптера проходит
		// сквозь движок кеша без заворота и доходит до клиента как 503,
		// а не падает в default-ветку 502.
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
		t.Cleanup(up.Close)
		clock := testutil.NewManualClock(time.Unix(0, 0))
		engine := cacheengine.New(unavailableStorage{}, testutil.NewFakeObjectIndex(), up.Client(), clock, cacheengine.Config{}, nil)
		eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL}
		h := BuildPublicRouter(Deps{Cache: engine, Ecosystems: map[string]port.Ecosystem{"t": eco}})
		if rec := get(t, h, "/t/pkg/a.deb"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("код = %d, хочу 503", rec.Code)
		}
	})
	t.Run("сбой носителя на write-пути (MISS-store) → 503", func(t *testing.T) {
		// Полный путь записи (сессия 60): Put хранилища отказывает
		// классифицированной недоступностью при качании MISS — клиент
		// получает 503 «наш инстанс», а не 502 «виноват upstream».
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
		t.Cleanup(up.Close)
		clock := testutil.NewManualClock(time.Unix(0, 0))
		engine := cacheengine.New(writeFailStorage{testutil.NewFakeStorage(clock)}, testutil.NewFakeObjectIndex(), up.Client(), clock, cacheengine.Config{}, nil)
		eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL}
		h := BuildPublicRouter(Deps{Cache: engine, Ecosystems: map[string]port.Ecosystem{"t": eco}})
		if rec := get(t, h, "/t/pkg/a.deb"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("код = %d, хочу 503", rec.Code)
		}
	})
}

// TestProxyContentTypeAllowlist — Content-Type ответа прокси не
// passthrough, а allowlist (сессия 78): рендеримые типы злого upstream
// не доходят до браузера (фишинг/дефейс в origin зеркала), пакетные
// расширения маппятся на честный тип, внестоловые расширения с честным
// upstream-типом проходят (контракт MISS↔HIT идентичности заголовков,
// сессия 69). nosniff ставится middleware поверх всех ответов.
func TestProxyContentTypeAllowlist(t *testing.T) {
	t.Run("злой text/html на индексе → octet-stream", func(t *testing.T) {
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html><body>phishing</body></html>")
		})
		rec := get(t, h, "/t/idx/dists/stable/Release")
		if rec.Code != http.StatusOK {
			t.Fatalf("код = %d, тело %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q, хочу application/octet-stream", got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, хочу nosniff", got)
		}
	})
	t.Run("deb-путь с честным типом → маппится, как заявлено", func(t *testing.T) {
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
			_, _ = io.WriteString(w, "deb-bytes")
		})
		rec := get(t, h, "/t/pkg/pool/main/a/apt/apt_1.0_amd64.deb")
		if got := rec.Header().Get("Content-Type"); got != "application/vnd.debian.binary-package" {
			t.Errorf("Content-Type = %q, хочу application/vnd.debian.binary-package", got)
		}
	})
	t.Run("внестоловое расширение с честным типом проходит", func(t *testing.T) {
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-contract")
			_, _ = io.WriteString(w, "x")
		})
		rec := get(t, h, "/t/idx/obj.bin")
		if got := rec.Header().Get("Content-Type"); got != "application/x-contract" {
			t.Errorf("Content-Type = %q, хочу application/x-contract", got)
		}
	})
	t.Run("злой text/xml с xml-stylesheet PI → octet-stream", func(t *testing.T) {
		// XSLT-XSS (верификация Р6): честно объявленный text/xml с PI
		// рендерится браузером как XSLT — тот же threat-model, что
		// text/html, блокируется тем же блоклистом.
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, `<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="evil.xsl"?><d/>`)
		})
		rec := get(t, h, "/t/idx/dists/stable/Release")
		if rec.Code != http.StatusOK {
			t.Fatalf("код = %d, тело %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q, хочу application/octet-stream", got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, хочу nosniff", got)
		}
	})
	t.Run("честный text/xml на .xml-пути → тоже octet-stream", func(t *testing.T) {
		// Единая точка защиты: renderable-блоклист гоняет тип в
		// octet-stream независимо от расширения пути.
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = io.WriteString(w, `<d/>`)
		})
		rec := get(t, h, "/t/idx/doc.xml")
		if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q, хочу application/octet-stream", got)
		}
	})
	t.Run("пакетное расширение в верхнем регистре маппится", func(t *testing.T) {
		// A.DEB — реальное имя пакета: честный тип по ToLower-таблице,
		// а не upstream-тип злого сервера.
		h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-evil")
			_, _ = io.WriteString(w, "x")
		})
		rec := get(t, h, "/t/pkg/pool/PACKAGE_1.0_amd64.DEB")
		if got := rec.Header().Get("Content-Type"); got != "application/vnd.debian.binary-package" {
			t.Errorf("Content-Type = %q, хочу application/vnd.debian.binary-package", got)
		}
	})
}

func TestProxyStaleServedWithWarning(t *testing.T) {
	requests := 0
	h, clock, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
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
		t.Errorf("Warning = %q, хочу 111", got)
	}
}

// scrapeMetrics — exposition-текст /metrics из экспортера (smoke-проверка
// наличия метрик по подстрокам, без декодирования формата).
func scrapeMetrics(t *testing.T, h *metrics.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// TestMetricsLatencyObserved — request_duration_seconds наполняется
// реальным трафиком с корректными (method, status) (аудит 2026-08-30:
// Observe-методы звались только из тестов, гистограмма была пустой).
func TestMetricsLatencyObserved(t *testing.T) {
	h, _, _, exporter, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload")
	})
	get(t, h, "/t/pkg/a.deb")
	get(t, h, "/nosuch/pkg/a.deb") // неизвестная экосистема → 404
	body := scrapeMetrics(t, exporter)
	if !strings.Contains(body, `khrazhevnik_request_duration_seconds_count{method="GET",status="200"} 1`) {
		t.Errorf("нет наблюдения GET/200 в request_duration_seconds:\n%s", body)
	}
	if !strings.Contains(body, `khrazhevnik_request_duration_seconds_count{method="GET",status="404"} 1`) {
		t.Errorf("нет наблюдения GET/404 в request_duration_seconds:\n%s", body)
	}
}

// TestMetricsObjectBytesObserved — object_bytes наполняется в точке
// прокси-отдачи: размер скопированного тела + имя экосистемы.
func TestMetricsObjectBytesObserved(t *testing.T) {
	h, _, _, exporter, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload")
	})
	get(t, h, "/t/pkg/a.deb")
	body := scrapeMetrics(t, exporter)
	if !strings.Contains(body, `khrazhevnik_object_bytes_count{ecosystem="t"} 1`) {
		t.Errorf("нет наблюдения object_bytes для eco=t:\n%s", body)
	}
	if !strings.Contains(body, `khrazhevnik_object_bytes_sum{ecosystem="t"} 7`) {
		t.Errorf("сумма object_bytes != 7 байтам:\n%s", body)
	}
}
