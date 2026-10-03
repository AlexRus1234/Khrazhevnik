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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Eviction — счётчики и гистограмма авто-очистки кеша pull-through прокси
// (eviction.Engine/Runner, сессия 201). Прямой аналог Retention с
// префиксом eviction: чистка кеша — не HTTP-транзакция и не per-eco
// разрез. Значения движок не пишет сам (метрики НЕ в движке, прецедент
// 119/120/171) — их наполняют хуки в wire: OnApply даёт счётчики
// удалённого и длительность, OnPass (Runner) — отметку времени прохода.
// Методы принимают примитивы, а не eviction.Result: metrics — leaf-пакет,
// импорт engine/… создал бы цикл.
type Eviction struct {
	RunsTotal          atomic.Int64
	DeletedKeysTotal   atomic.Int64
	DeletedBytesTotal  atomic.Int64
	FailedDeletesTotal atomic.Int64
	// LastPassUnix — секунды Unix последнего прохода по remote (gauge):
	// по нему ревизия видит, что цикл вообще жив, и когда он был.
	LastPassUnix atomic.Int64

	runsTotal     *prometheus.Desc
	deletedKeys   *prometheus.Desc
	deletedBytes  *prometheus.Desc
	failedDeletes *prometheus.Desc
	lastPass      *prometheus.Desc
	duration      prometheus.Histogram
}

// NewEviction собирает коллектор eviction. Гистограмма — stateful
// prometheus.Histogram (как у Retention/StorageGC), поэтому создаётся
// здесь, а регистрируется вместе со счётчиками через Register. Границы
// корзин — как у ретеншна и чистки хранилища: проход по remote —
// секунды-минуты, а не миллисекунды.
func NewEviction() *Eviction {
	return &Eviction{
		runsTotal:     prometheus.NewDesc("khrazhevnik_eviction_runs_total", "Completed eviction passes over one remote.", nil, nil),
		deletedKeys:   prometheus.NewDesc("khrazhevnik_eviction_deleted_keys_total", "Storage objects deleted by eviction.", nil, nil),
		deletedBytes:  prometheus.NewDesc("khrazhevnik_eviction_deleted_bytes_total", "Bytes freed by eviction.", nil, nil),
		failedDeletes: prometheus.NewDesc("khrazhevnik_eviction_failed_deletes_total", "Objects eviction failed to delete.", nil, nil),
		lastPass:      prometheus.NewDesc("khrazhevnik_eviction_last_pass_timestamp", "Unix timestamp of the last eviction pass over a remote.", nil, nil),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "khrazhevnik_eviction_duration_seconds",
			Help:    "Duration of one eviction apply pass over a remote in seconds.",
			Buckets: []float64{0.01, 0.1, 0.5, 1, 5, 30, 120, 600},
		}),
	}
}

// ObserveApply фиксирует итоги одного Apply: +1 к RunsTotal, прирост
// удалённого/освобождённого/сбойного и наблюдение длительности (её
// измеряет движок — Result.Duration). Вызывается из OnApply-хука движка,
// поэтому считает и ручные проходы (API сессии 202), и суточные.
// Освобождение байт копится и в dry-run — там оно равно нулю (удалений
// нет), лживой серии не возникает.
func (e *Eviction) ObserveApply(deletedKeys, deletedBytes, failedDeletes int64, seconds float64) {
	e.RunsTotal.Add(1)
	e.DeletedKeysTotal.Add(deletedKeys)
	e.DeletedBytesTotal.Add(deletedBytes)
	e.FailedDeletesTotal.Add(failedDeletes)
	e.duration.Observe(seconds)
}

// ObservePass ставит отметку времени прохода по remote (gauge) — из
// OnPass-хука Runner'а. Время приходит от вызывающего (wire: port.Clock):
// metrics — leaf-пакет без часов, а собственная привязка к time.Now()
// разошлась бы с доменным временем инстанса.
func (e *Eviction) ObservePass(at time.Time) {
	e.LastPassUnix.Store(at.Unix())
}

// Register регистрирует счётчики и гистограмму в Registry. Вызывается wire
// только при включённых метриках; повторная регистрация на одном Registry
// — panic (один Registry на процесс, как у Retention).
func (e *Eviction) Register(reg prometheus.Registerer) {
	reg.MustRegister(e)
	reg.MustRegister(e.duration)
}

// Describe реализует prometheus.Collector: статичные описания счётчиков и
// gauge; гистограмма описывает себя сама.
func (e *Eviction) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.runsTotal
	ch <- e.deletedKeys
	ch <- e.deletedBytes
	ch <- e.failedDeletes
	ch <- e.lastPass
}

// Collect отдаёт текущие значения. Корневые счётчики eviction — единственный
// источник (per-eco разрезов у eviction нет).
func (e *Eviction) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(e.runsTotal, prometheus.CounterValue, float64(e.RunsTotal.Load()))
	ch <- prometheus.MustNewConstMetric(e.deletedKeys, prometheus.CounterValue, float64(e.DeletedKeysTotal.Load()))
	ch <- prometheus.MustNewConstMetric(e.deletedBytes, prometheus.CounterValue, float64(e.DeletedBytesTotal.Load()))
	ch <- prometheus.MustNewConstMetric(e.failedDeletes, prometheus.CounterValue, float64(e.FailedDeletesTotal.Load()))
	ch <- prometheus.MustNewConstMetric(e.lastPass, prometheus.GaugeValue, float64(e.LastPassUnix.Load()))
}
