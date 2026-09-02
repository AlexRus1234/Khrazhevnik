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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"khrazhevnik/internal/core/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

// TestObserveMetricsMethodAllowlist — произвольный RFC-7230 token в
// r.Method (chi гоняет Use-стек до method-роутинга) не создаёт ребёнка
// HistogramVec: метод вне allowlist записывается как "other", обычные
// методы — как есть (лейбл-кардинальность ограничена константой).
func TestObserveMetricsMethodAllowlist(t *testing.T) {
	h := metrics.NewHandler(metrics.NewCache(), prometheus.NewRegistry())
	observe := ObserveMetrics(h)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// POST до FROBNICATE: если бы сырой метод утёк, "other" уже
	// существовал бы как отдельный ребёнок и проверка была бы пустой.
	observe(next).ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/x", nil))
	observe(next).ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest("FROBNICATE", "/x", nil))

	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`method="other"`,
		`method="POST"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в /metrics нет %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `method="FROBNICATE"`) {
		t.Errorf("сырой метод утёк в лейбл:\n%s", body)
	}
}
