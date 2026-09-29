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

// Retention — счётчики и гистограмма ретеншна личных репозиториев
// (retention.Engine/Runner, сессия 171). Отдельный коллектор рядом с
// StorageGC: чистка личных репо — не HTTP-транзакция кеша и не per-eco
// разрез. Значения движок не пишет сам (метрики НЕ в движке,
// прецедент 119/120) — их наполняют хуки в wire: OnApply даёт счётчики
// удалённого и длительность, OnPass (Runner) — отметку времени прохода.
// Методы принимают примитивы, а не retention.Result: metrics —
// leaf-пакет, импорт engine/… создал бы цикл.
type Retention struct {
	RunsTotal          atomic.Int64
	DeletedKeysTotal   atomic.Int64
	DeletedBytesTotal  atomic.Int64
	FailedDeletesTotal atomic.Int64
	// LastPassUnix — секунды Unix последнего прохода по репо (gauge):
	// по нему ревизия видит, что цикл вообще жив, и когда он был.
	LastPassUnix atomic.Int64

	runsTotal     *prometheus.Desc
	deletedKeys   *prometheus.Desc
	deletedBytes  *prometheus.Desc
	failedDeletes *prometheus.Desc
	lastPass      *prometheus.Desc
	duration      prometheus.Histogram
}

// NewRetention собирает коллектор ретеншна. Гистограмма — stateful
// prometheus.Histogram (как у StorageGC и latency-метрик Handler'а),
// поэтому создаётся здесь, а регистрируется вместе со счётчиками
// через Register. Границы корзин — как у чистки хранилища: проход по
// репо — секунды-минуты, а не миллисекунды.
func NewRetention() *Retention {
	return &Retention{
		runsTotal:     prometheus.NewDesc("khrazhevnik_retention_runs_total", "Completed retention passes over one repository.", nil, nil),
		deletedKeys:   prometheus.NewDesc("khrazhevnik_retention_deleted_keys_total", "Storage objects deleted by retention.", nil, nil),
		deletedBytes:  prometheus.NewDesc("khrazhevnik_retention_deleted_bytes_total", "Bytes freed by retention.", nil, nil),
		failedDeletes: prometheus.NewDesc("khrazhevnik_retention_failed_deletes_total", "Objects retention failed to delete.", nil, nil),
		lastPass:      prometheus.NewDesc("khrazhevnik_retention_last_pass_timestamp", "Unix timestamp of the last retention pass over a repository.", nil, nil),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "khrazhevnik_retention_duration_seconds",
			Help:    "Duration of one retention apply pass over a repository in seconds.",
			Buckets: []float64{0.01, 0.1, 0.5, 1, 5, 30, 120, 600},
		}),
	}
}

// ObserveApply фиксирует итоги одного Apply: +1 к RunsTotal, прирост
// удалённого/освобождённого/сбойного и наблюдение длительности (её
// измеряет движок — Result.Duration). Вызывается из OnApply-хука
// движка, поэтому считает и ручные проходы (API сессии 173), и
// суточные. Освобождение байт копится и в dry-run — там оно равно нулю
// (удалений нет), лживой серии не возникает.
func (r *Retention) ObserveApply(deletedKeys, deletedBytes, failedDeletes int64, seconds float64) {
	r.RunsTotal.Add(1)
	r.DeletedKeysTotal.Add(deletedKeys)
	r.DeletedBytesTotal.Add(deletedBytes)
	r.FailedDeletesTotal.Add(failedDeletes)
	r.duration.Observe(seconds)
}

// ObservePass ставит отметку времени прохода по репо (gauge) — из
// OnPass-хука Runner'а. Время приходит от вызывающего (wire: port.Clock):
// metrics — leaf-пакет без часов, а собственная привязка к time.Now()
// разошлась бы с доменным временем инстанса.
func (r *Retention) ObservePass(at time.Time) {
	r.LastPassUnix.Store(at.Unix())
}

// Register регистрирует счётчики и гистограмму в Registry. Вызывается
// wire только при включённых метриках; повторная регистрация на одном
// Registry — panic (один Registry на процесс, как у StorageGC).
func (r *Retention) Register(reg prometheus.Registerer) {
	reg.MustRegister(r)
	reg.MustRegister(r.duration)
}

// Describe реализует prometheus.Collector: статичные описания счётчиков
// и gauge; гистограмма описывает себя сама.
func (r *Retention) Describe(ch chan<- *prometheus.Desc) {
	ch <- r.runsTotal
	ch <- r.deletedKeys
	ch <- r.deletedBytes
	ch <- r.failedDeletes
	ch <- r.lastPass
}

// Collect отдаёт текущие значения. Корневые счётчики ретеншна, в
// отличие от Cache, — единственный источник (per-eco разрезов у
// ретеншна нет).
func (r *Retention) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(r.runsTotal, prometheus.CounterValue, float64(r.RunsTotal.Load()))
	ch <- prometheus.MustNewConstMetric(r.deletedKeys, prometheus.CounterValue, float64(r.DeletedKeysTotal.Load()))
	ch <- prometheus.MustNewConstMetric(r.deletedBytes, prometheus.CounterValue, float64(r.DeletedBytesTotal.Load()))
	ch <- prometheus.MustNewConstMetric(r.failedDeletes, prometheus.CounterValue, float64(r.FailedDeletesTotal.Load()))
	ch <- prometheus.MustNewConstMetric(r.lastPass, prometheus.GaugeValue, float64(r.LastPassUnix.Load()))
}
