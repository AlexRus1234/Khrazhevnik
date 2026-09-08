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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestCacheEachEcosystemSorted(t *testing.T) {
	c := NewCache()
	// Создаём в обратном лексическом порядке — EachEcosystem должен
	// отдать по алфавиту.
	c.ForEcosystem("rpmmmd")
	c.ForEcosystem("apt")
	c.ForEcosystem("nix")

	var got []string
	c.EachEcosystem(func(name string, _ *Cache) { got = append(got, name) })
	want := []string{"apt", "nix", "rpmmmd"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("EachEcosystem = %v, хочу %v", got, want)
	}
}

func TestCacheEachEcosystemEmpty(t *testing.T) {
	c := NewCache()
	called := false
	c.EachEcosystem(func(name string, _ *Cache) { called = true })
	if called {
		t.Fatal("EachEcosystem вызвался на пустом реестре")
	}
}

func TestHandlerExposesAllMetricNames(t *testing.T) {
	c := NewCache()
	// Корневые поля движком не пишутся (сессия 83): весь инкремент —
	// per-eco записи, тотальные серии проверяются суммами.
	apt := c.ForEcosystem("apt")
	apt.Hits.Add(5)
	apt.Misses.Add(2)
	apt.StaleServed.Add(1)
	apt.NegativeHits.Add(1)
	apt.UpstreamErrors.Add(2)
	apt.BytesFromUpstream.Add(512)
	apt.BytesToClients.Add(1024)
	apt.Packages.Add(3)

	rpmmmd := c.ForEcosystem("rpmmmd")
	rpmmmd.Hits.Add(1)
	rpmmmd.Misses.Add(1)
	rpmmmd.StaleServed.Add(1)
	rpmmmd.UpstreamErrors.Add(2)
	rpmmmd.BytesFromUpstream.Add(512)
	rpmmmd.BytesToClients.Add(1024)

	h := NewHandler(c, prometheus.NewRegistry())
	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"khrazhevnik_cache_hits_total",
		"khrazhevnik_cache_misses_total",
		"khrazhevnik_cache_stale_served_total",
		"khrazhevnik_cache_negative_hits_total",
		"khrazhevnik_cache_upstream_errors_total",
		"khrazhevnik_cache_bytes_from_upstream_total",
		"khrazhevnik_cache_bytes_to_clients_total",
		"khrazhevnik_cache_ecosystem_packages",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в /metrics нет имени %q:\n%s", want, body)
		}
	}
	// Лейблы экосистем присутствуют.
	if !strings.Contains(body, `ecosystem="apt"`) {
		t.Errorf("нет лейбла ecosystem=\"apt\":\n%s", body)
	}
	if !strings.Contains(body, `ecosystem="rpmmmd"`) {
		t.Errorf("нет лейбла ecosystem=\"rpmmmd\":\n%s", body)
	}
	// Проекция на чтении: total = сумма per-eco (hits 6 = 5+1,
	// misses 3, bytes_from_upstream 1024, bytes_to_clients 2048).
	if !strings.Contains(body, "khrazhevnik_cache_hits_total 6") {
		t.Errorf("total hits не равен 6:\n%s", body)
	}
	if !strings.Contains(body, "khrazhevnik_cache_misses_total 3") {
		t.Errorf("total misses не равен 3:\n%s", body)
	}
	if !strings.Contains(body, "khrazhevnik_cache_stale_served_total 2") {
		t.Errorf("total stale не равен 2:\n%s", body)
	}
	if !strings.Contains(body, "khrazhevnik_cache_negative_hits_total 1") {
		t.Errorf("total negative не равен 1:\n%s", body)
	}
	if !strings.Contains(body, "khrazhevnik_cache_upstream_errors_total 4") {
		t.Errorf("total upstream_errors не равен 4:\n%s", body)
	}
	if !strings.Contains(body, "khrazhevnik_cache_bytes_from_upstream_total 1024") {
		t.Errorf("total bytes_from_upstream не равен 1024:\n%s", body)
	}
	if !strings.Contains(body, "khrazhevnik_cache_bytes_to_clients_total 2048") {
		t.Errorf("total bytes_to_clients не равен 2048:\n%s", body)
	}
	if !strings.Contains(body, `khrazhevnik_cache_ecosystem_hits_total{ecosystem="apt"} 5`) {
		t.Errorf("apt hits не равен 5:\n%s", body)
	}
	// Gauge per-eco: значение по лейблу, глобальной серии у packages нет.
	if !strings.Contains(body, `khrazhevnik_cache_ecosystem_packages{ecosystem="apt"} 3`) {
		t.Errorf("apt packages не равен 3:\n%s", body)
	}
}

func TestHandlerDefaultsWhenNil(t *testing.T) {
	// nil-аргументы не должны паниковать — NewHandler подставляет
	// пустой Cache и свежий Registry.
	h := NewHandler(nil, nil)
	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	// Пустой Cache всё равно экспонирует все имена (с нулями).
	for _, want := range []string{
		"khrazhevnik_cache_hits_total 0",
		"khrazhevnik_cache_misses_total 0",
		"khrazhevnik_cache_bytes_to_clients_total 0",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("в /metrics нет %q", want)
		}
	}
}

func TestHandlerRegistryReuseRejected(t *testing.T) {
	// Повторный NewHandler на том же Registry — panic на Register:
	// в боевой код такой путь не ведёт (один Registry на процесс),
	// но контракт прометея соблюдаем.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("повторный NewHandler на одном Registry не вызвал panic")
		}
	}()
	reg := prometheus.NewRegistry()
	_ = NewHandler(NewCache(), reg)
	_ = NewHandler(NewCache(), reg)
}

func TestHandlerObserveLatencyAndObjectBytes(t *testing.T) {
	c := NewCache()
	h := NewHandler(c, prometheus.NewRegistry())
	h.ObserveRequestLatency("GET", "200", 0.012)
	h.ObserveRequestLatency("GET", "404", 0.003)
	h.ObserveObjectBytes("apt", 2048)
	h.ObserveObjectBytes("apt", 1<<20)

	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	// Prometheus сортирует лейблы по алфавиту: method,status,le.
	// Числовые границы bucket'ов выводятся в научной нотации.
	for _, want := range []string{
		"khrazhevnik_request_duration_seconds_bucket",
		`khrazhevnik_request_duration_seconds_bucket{method="GET",status="200",le="0.05"} 1`,
		`khrazhevnik_request_duration_seconds_bucket{method="GET",status="404",le="0.005"} 1`,
		"khrazhevnik_object_bytes_bucket",
		`khrazhevnik_object_bytes_bucket{ecosystem="apt",le="1.048576e+06"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в /metrics нет %q:\n%s", want, body)
		}
	}
}

func TestHandlerObserveNilSafe(t *testing.T) {
	// Observe* на нулевом Handler (после NewHandler(nil,nil)) не паникует.
	h := NewHandler(nil, nil)
	h.ObserveRequestLatency("GET", "200", 0.1)
	h.ObserveObjectBytes("apt", 100)
}
