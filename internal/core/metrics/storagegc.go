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
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// StorageGC — счётчики и гистограмма выметающей чистки хранилища
// (storagegc.Sweeper, сессии 119–120). Отдельный коллектор рядом с
// Cache: чистка — не HTTP-транзакция кеша и не per-eco разрез.
// Значения движок не пишет сам (метрики НЕ в движке, сессия 119) —
// их наполняет OnSweep-хук в wire из Result; методы принимают
// примитивы, а не storagegc.Result: metrics — leaf-пакет, импорт
// engine/… создал бы цикл.
type StorageGC struct {
	RunsTotal          atomic.Int64
	DeletedKeysTotal   atomic.Int64
	DeletedBytesTotal  atomic.Int64
	FailedDeletesTotal atomic.Int64

	runsTotal     *prometheus.Desc
	deletedKeys   *prometheus.Desc
	deletedBytes  *prometheus.Desc
	failedDeletes *prometheus.Desc
	duration      prometheus.Histogram
}

// NewStorageGC собирает коллектор чистки. Гистограмма — stateful
// prometheus.Histogram (как latency/object_bytes Handler'а), поэтому
// создаётся здесь, а регистрируется вместе со счётчиками через
// Register.
func NewStorageGC() *StorageGC {
	return &StorageGC{
		runsTotal:     prometheus.NewDesc("khrazhevnik_storage_gc_runs_total", "Completed storage garbage-collection runs.", nil, nil),
		deletedKeys:   prometheus.NewDesc("khrazhevnik_storage_gc_deleted_keys_total", "Storage objects deleted by garbage collection.", nil, nil),
		deletedBytes:  prometheus.NewDesc("khrazhevnik_storage_gc_deleted_bytes_total", "Bytes freed by storage garbage collection.", nil, nil),
		failedDeletes: prometheus.NewDesc("khrazhevnik_storage_gc_failed_deletes_total", "Objects garbage collection failed to delete.", nil, nil),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "khrazhevnik_storage_gc_duration_seconds",
			Help:    "Duration of one storage garbage-collection run in seconds.",
			Buckets: []float64{0.01, 0.1, 0.5, 1, 5, 30, 120, 600},
		}),
	}
}

// ObserveRun фиксирует итоги одного прохода: +1 к RunsTotal, прирост
// счётчиков удалённого/освобождённого/сбойного и наблюдение
// длительности. Освобождение байт копится и в dry-run — там оно равно
// нулю (удалений нет), поэтому лживой серии не возникает.
func (g *StorageGC) ObserveRun(deletedKeys, deletedBytes, failedDeletes int64, seconds float64) {
	g.RunsTotal.Add(1)
	g.DeletedKeysTotal.Add(deletedKeys)
	g.DeletedBytesTotal.Add(deletedBytes)
	g.FailedDeletesTotal.Add(failedDeletes)
	g.duration.Observe(seconds)
}

// Register регистрирует счётчики и гистограмму в Registry. Вызывается
// wire только при включённых метриках; повторная регистрация на одном
// Registry — panic (один Registry на процесс, как у Handler).
func (g *StorageGC) Register(reg prometheus.Registerer) {
	reg.MustRegister(g)
	reg.MustRegister(g.duration)
}

// Describe реализует prometheus.Collector: статичные описания
// счётчиков; гистограмма описывает себя сама.
func (g *StorageGC) Describe(ch chan<- *prometheus.Desc) {
	ch <- g.runsTotal
	ch <- g.deletedKeys
	ch <- g.deletedBytes
	ch <- g.failedDeletes
}

// Collect отдаёт текущие значения счётчиков. Корневые счётчики
// чистки, в отличие от Cache, — единственный источник (per-eco
// разрезов у чистки нет).
func (g *StorageGC) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(g.runsTotal, prometheus.CounterValue, float64(g.RunsTotal.Load()))
	ch <- prometheus.MustNewConstMetric(g.deletedKeys, prometheus.CounterValue, float64(g.DeletedKeysTotal.Load()))
	ch <- prometheus.MustNewConstMetric(g.deletedBytes, prometheus.CounterValue, float64(g.DeletedBytesTotal.Load()))
	ch <- prometheus.MustNewConstMetric(g.failedDeletes, prometheus.CounterValue, float64(g.FailedDeletesTotal.Load()))
}
