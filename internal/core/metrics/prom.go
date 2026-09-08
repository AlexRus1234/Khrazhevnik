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

// Экспозиция счётчиков кеша в Prometheus. Живёт в leaf-пакете metrics:
// не импортирует другие пакеты ядра, разрывает цикл «web тянет engine
// ради метрик». Web-слой регистрирует Registry через SetCache и потом
// отдаёт /metrics из Deps.

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler — экспортер Prometheus поверх *Cache: регистрирует счётчики
// в переданном Registry и обновляет их значения перед каждой сборкой
// /metrics. Коллектор ленивый: новые экосистемы, появившиеся после
// старта, попадают в вывод по факту.
//
// Помимо счётчиков кеша Handler держит две гистограммы, заполняемые
// web-слоем через Observe*: latency запросов обоих слушателей
// (публичный и админский) и размер отданных объектов. Гистограммы —
// настоящие prometheus.Histogram
// (а не const-metric), потому что значения накапливаются между scrape.
type Handler struct {
	cache    *Cache
	registry *prometheus.Registry
	// Коллекторы-счётчики создаются один раз при New; Collect
	// перезаливает значения из atomic-счётчиков Cache.
	hits, misses, stale, negative, upstreamErrors    *prometheus.Desc
	backgroundPanics                                 *prometheus.Desc
	bytesFromUpstream, bytesToClients                *prometheus.Desc
	ecoHits, ecoMisses, ecoStale, ecoNegative        *prometheus.Desc
	ecoUpstreamErrors, ecoBytesFromUp, ecoBytesToCli *prometheus.Desc
	ecoPackages                                      *prometheus.Desc
	// Гистограммы — stateful, живут между scrape.
	requestLatency *prometheus.HistogramVec
	objectBytes    *prometheus.HistogramVec
}

// NewHandler собирает экспортер на переданном Registry. Registry
// уникален на процесс (один /metrics — один Registry); несколько
// Handler на одном Registry дадут panic на Register — это ошибка
// программиста, а не рантайма.
//
// Имена глобальных и per-ecosystem метрик различаются суффиксом
// `_ecosystem`: Prometheus запрещает одно имя с разными наборами
// лейблов, поэтому global totals и per-eco counters живут каждый под
// своим именем (глобал — без лейбла, per-eco — с `ecosystem`).
func NewHandler(cache *Cache, registry *prometheus.Registry) *Handler {
	if cache == nil {
		cache = NewCache()
	}
	if registry == nil {
		registry = prometheus.NewRegistry()
	}
	h := &Handler{
		cache:             cache,
		registry:          registry,
		hits:              prometheus.NewDesc("khrazhevnik_cache_hits_total", "Total cache hits.", nil, nil),
		misses:            prometheus.NewDesc("khrazhevnik_cache_misses_total", "Total cache misses.", nil, nil),
		stale:             prometheus.NewDesc("khrazhevnik_cache_stale_served_total", "Times stale copy served on upstream error (RFC 5861).", nil, nil),
		negative:          prometheus.NewDesc("khrazhevnik_cache_negative_hits_total", "Hits of negative cache (404/5xx served without upstream).", nil, nil),
		upstreamErrors:    prometheus.NewDesc("khrazhevnik_cache_upstream_errors_total", "Upstream request failures.", nil, nil),
		bytesFromUpstream: prometheus.NewDesc("khrazhevnik_cache_bytes_from_upstream_total", "Bytes pulled from upstream.", nil, nil),
		bytesToClients:    prometheus.NewDesc("khrazhevnik_cache_bytes_to_clients_total", "Bytes streamed to clients.", nil, nil),
		backgroundPanics:  prometheus.NewDesc("khrazhevnik_cache_background_panics_total", "Panics recovered from cache background operations.", nil, nil),
		ecoHits:           prometheus.NewDesc("khrazhevnik_cache_ecosystem_hits_total", "Cache hits per ecosystem.", []string{"ecosystem"}, nil),
		ecoMisses:         prometheus.NewDesc("khrazhevnik_cache_ecosystem_misses_total", "Cache misses per ecosystem.", []string{"ecosystem"}, nil),
		ecoStale:          prometheus.NewDesc("khrazhevnik_cache_ecosystem_stale_served_total", "Stale served per ecosystem.", []string{"ecosystem"}, nil),
		ecoNegative:       prometheus.NewDesc("khrazhevnik_cache_ecosystem_negative_hits_total", "Negative-cache hits per ecosystem.", []string{"ecosystem"}, nil),
		ecoUpstreamErrors: prometheus.NewDesc("khrazhevnik_cache_ecosystem_upstream_errors_total", "Upstream errors per ecosystem.", []string{"ecosystem"}, nil),
		ecoBytesFromUp:    prometheus.NewDesc("khrazhevnik_cache_ecosystem_bytes_from_upstream_total", "Bytes from upstream per ecosystem.", []string{"ecosystem"}, nil),
		ecoBytesToCli:     prometheus.NewDesc("khrazhevnik_cache_ecosystem_bytes_to_clients_total", "Bytes to clients per ecosystem.", []string{"ecosystem"}, nil),
		// Gauge, не counter: значение — текущее число закешированных
		// immutable-объектов; сброс статистики и рестарт легитимно
		// роняют его, counter-семантика монотонности здесь ложная.
		ecoPackages: prometheus.NewDesc("khrazhevnik_cache_ecosystem_packages", "Cached immutable objects (packages) per ecosystem.", []string{"ecosystem"}, nil),
		requestLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "khrazhevnik_request_duration_seconds",
			Help:    "Request latency in seconds across both public and admin listeners.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
		}, []string{"method", "status"}),
		objectBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "khrazhevnik_object_bytes",
			Help:    "Size of objects served by the cache proxy (repo delivery is not covered).",
			Buckets: []float64{1 << 10, 1 << 16, 1 << 20, 10 << 20, 100 << 20, 1 << 30},
		}, []string{"ecosystem"}),
	}
	registry.MustRegister(h)
	registry.MustRegister(h.requestLatency)
	registry.MustRegister(h.objectBytes)
	return h
}

// Describe реализует prometheus.Collector: статичные описания счётчиков.
// Гистограммы регистрируются отдельно и сами описывают себя.
func (h *Handler) Describe(ch chan<- *prometheus.Desc) {
	ch <- h.hits
	ch <- h.misses
	ch <- h.stale
	ch <- h.negative
	ch <- h.upstreamErrors
	ch <- h.bytesFromUpstream
	ch <- h.bytesToClients
	ch <- h.backgroundPanics
	ch <- h.ecoHits
	ch <- h.ecoMisses
	ch <- h.ecoStale
	ch <- h.ecoNegative
	ch <- h.ecoUpstreamErrors
	ch <- h.ecoBytesFromUp
	ch <- h.ecoBytesToCli
	ch <- h.ecoPackages
}

// Collect собирает текущие значения счётчиков из Cache. Вызывается
// Prometheus-хендлером на каждый scrape /metrics. Источник значений —
// per-eco разрезы (сессия 83): глобальные серии — суммы per-eco,
// собранные в один проход EachEcosystem; backgroundPanics — как
// прежде из корня (у фонового удаления eco-контекста нет).
func (h *Handler) Collect(ch chan<- prometheus.Metric) {
	var hits, misses, stale, negative, upstreamErrors, bytesFromUpstream, bytesToClients int64
	h.cache.EachEcosystem(func(name string, m *Cache) {
		hits += m.Hits.Load()
		misses += m.Misses.Load()
		stale += m.StaleServed.Load()
		negative += m.NegativeHits.Load()
		upstreamErrors += m.UpstreamErrors.Load()
		bytesFromUpstream += m.BytesFromUpstream.Load()
		bytesToClients += m.BytesToClients.Load()
		ch <- prometheus.MustNewConstMetric(h.ecoHits, prometheus.CounterValue, float64(m.Hits.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoMisses, prometheus.CounterValue, float64(m.Misses.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoStale, prometheus.CounterValue, float64(m.StaleServed.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoNegative, prometheus.CounterValue, float64(m.NegativeHits.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoUpstreamErrors, prometheus.CounterValue, float64(m.UpstreamErrors.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoBytesFromUp, prometheus.CounterValue, float64(m.BytesFromUpstream.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoBytesToCli, prometheus.CounterValue, float64(m.BytesToClients.Load()), name)
		ch <- prometheus.MustNewConstMetric(h.ecoPackages, prometheus.GaugeValue, float64(m.Packages.Load()), name)
	})
	ch <- prometheus.MustNewConstMetric(h.hits, prometheus.CounterValue, float64(hits))
	ch <- prometheus.MustNewConstMetric(h.misses, prometheus.CounterValue, float64(misses))
	ch <- prometheus.MustNewConstMetric(h.stale, prometheus.CounterValue, float64(stale))
	ch <- prometheus.MustNewConstMetric(h.negative, prometheus.CounterValue, float64(negative))
	ch <- prometheus.MustNewConstMetric(h.upstreamErrors, prometheus.CounterValue, float64(upstreamErrors))
	ch <- prometheus.MustNewConstMetric(h.bytesFromUpstream, prometheus.CounterValue, float64(bytesFromUpstream))
	ch <- prometheus.MustNewConstMetric(h.bytesToClients, prometheus.CounterValue, float64(bytesToClients))
	ch <- prometheus.MustNewConstMetric(h.backgroundPanics, prometheus.CounterValue, float64(h.cache.BackgroundPanics.Load()))
}

// MetricsHandler — HTTP-хендлер /metrics из Registry. Вынесен сюда,
// чтобы web-слой не импортировал promhttp напрямую (прометеевский
// пакет — деталь экспозиции, а не доставки).
func (h *Handler) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(h.registry, promhttp.HandlerOpts{})
}

// ObserveRequestLatency фиксирует длительность запроса (оба слушателя:
// публичный и админский). method/status — лейблы (GET/200, GET/404, ...). Вызов из web-слоя
// после завершения хендлера; секунды — в float, как требует Prom.
func (h *Handler) ObserveRequestLatency(method, status string, seconds float64) {
	if h.requestLatency == nil {
		return
	}
	h.requestLatency.WithLabelValues(method, status).Observe(seconds)
}

// ObserveObjectBytes фиксирует размер объекта, отданного клиенту.
// ecosystem — лейбл; байты — в float, как требует Prom.
func (h *Handler) ObserveObjectBytes(ecosystem string, bytes float64) {
	if h.objectBytes == nil {
		return
	}
	h.objectBytes.WithLabelValues(ecosystem).Observe(bytes)
}
