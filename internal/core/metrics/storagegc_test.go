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
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TestStorageGCObserveRun — счётчики чистки накапливаются из примитивов
// (OnSweep-хук в wire передаёт Result).
func TestStorageGCObserveRun(t *testing.T) {
	g := NewStorageGC()
	g.ObserveRun(3, 1024, 1, 0.25)
	g.ObserveRun(0, 0, 0, 0.5)

	if got := g.RunsTotal.Load(); got != 2 {
		t.Errorf("RunsTotal = %d, хочу 2", got)
	}
	if got := g.DeletedKeysTotal.Load(); got != 3 {
		t.Errorf("DeletedKeysTotal = %d, хочу 3", got)
	}
	if got := g.DeletedBytesTotal.Load(); got != 1024 {
		t.Errorf("DeletedBytesTotal = %d, хочу 1024", got)
	}
	if got := g.FailedDeletesTotal.Load(); got != 1 {
		t.Errorf("FailedDeletesTotal = %d, хочу 1", got)
	}
}

// TestStorageGCRegisterExposesNames — /metrics отдаёт все серии чистки
// под префиксом khrazhevnik_storage_gc_.
func TestStorageGCRegisterExposesNames(t *testing.T) {
	g := NewStorageGC()
	g.ObserveRun(3, 1024, 1, 0.25)

	reg := prometheus.NewRegistry()
	g.Register(reg)
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"khrazhevnik_storage_gc_runs_total 1",
		"khrazhevnik_storage_gc_deleted_keys_total 3",
		"khrazhevnik_storage_gc_deleted_bytes_total 1024",
		"khrazhevnik_storage_gc_failed_deletes_total 1",
		"khrazhevnik_storage_gc_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в /metrics нет %q:\n%s", want, body)
		}
	}
}
