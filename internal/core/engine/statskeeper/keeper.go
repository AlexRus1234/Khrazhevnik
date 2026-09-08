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

// Package statskeeper — персистентность счётчиков статистики кеша:
// снапшот per-eco атомиков пишется в cache_stats периодическим флашем
// и сеется обратно при старте — рестарт процесса больше не обнуляет
// статистику живого кеша. Отдельный компонент рядом с движком кеша,
// а не его часть: движок не получает ни горутин, ни порта БД (его
// зона — HTTP-транзакция кеша; прецедент — Scheduler рядом с
// mirror.Engine).
package statskeeper

import (
	"context"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
)

// Keeper — фоновый цикл флаша per-eco счётчиков stats-разрезов в
// StatsStore (cache_stats) и посадка снапшота из БД при старте.
type Keeper struct {
	m        *metrics.Cache
	store    port.StatsStore
	clock    port.Clock
	interval time.Duration

	// OnError — колбэк для ошибок тик-флашей (инжектится wire'ом, как
	// Scheduler.ErrorHook): сбой БД не гасит цикл, но и не теряется
	// молча.
	OnError func(error)

	// mu охраняет cancel/done — поля жизненного цикла Run/Stop.
	mu     sync.Mutex
	cancel context.CancelFunc // nil до Run и после Stop
	done   chan struct{}      // закрытие = горутина-тикер вышла
}

// New собирает keeper'а поверх per-eco атомиков движка кеша; interval
// — период фона (0 недопустим — отсекается wire'ом, тикер с нулевым
// интервалом паникует).
func New(m *metrics.Cache, store port.StatsStore, clock port.Clock, interval time.Duration) *Keeper {
	return &Keeper{m: m, store: store, clock: clock, interval: interval}
}

// Load сеет снапшот из БД в per-eco атомики. Вызывается один раз при
// старте до Run — гонки flush↔загрузка нет по конструкции.
func (k *Keeper) Load(ctx context.Context) error {
	rows, err := k.store.StatsSnapshot(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		m := k.m.ForEcosystem(row.Ecosystem)
		m.Hits.Store(row.Hits)
		m.Misses.Store(row.Misses)
		m.StaleServed.Store(row.StaleServed)
		m.NegativeHits.Store(row.NegativeHits)
		m.UpstreamErrors.Store(row.UpstreamErrors)
		m.BytesFromUpstream.Store(row.BytesFromUpstream)
		m.BytesToClients.Store(row.BytesToClients)
		m.Packages.Store(row.Packages)
	}
	return nil
}

// Flush пишет текущие значения per-eco атомиков одним снапшотом
// (одна транзакция SaveStatsSnapshot). Пустой реестр — no-op без
// похода в БД: инстанс, ещё не обслуживавший трафик, не создаёт строк.
func (k *Keeper) Flush(ctx context.Context) error {
	rows := make([]domain.CacheStatsRow, 0, 8)
	// EachEcosystem итерирует под мьютексом реестра — ForEcosystem
	// внутри yield запрещён (вложенная блокировка, cache.go ForEcosystem):
	// в callback только чтение переданного *metrics.Cache.
	k.m.EachEcosystem(func(name string, m *metrics.Cache) {
		rows = append(rows, domain.CacheStatsRow{
			Ecosystem:         name,
			Hits:              m.Hits.Load(),
			Misses:            m.Misses.Load(),
			StaleServed:       m.StaleServed.Load(),
			NegativeHits:      m.NegativeHits.Load(),
			UpstreamErrors:    m.UpstreamErrors.Load(),
			BytesFromUpstream: m.BytesFromUpstream.Load(),
			BytesToClients:    m.BytesToClients.Load(),
			Packages:          m.Packages.Load(),
			UpdatedAt:         k.clock.Now(),
		})
	})
	if len(rows) == 0 {
		return nil
	}
	return k.store.SaveStatsSnapshot(ctx, rows)
}

// Run запускает горутину-тикер: раз в interval — Flush. Пауза —
// time.Ticker, а не port.Clock: момент снятия показаний времени не
// важен (счётчики кумулятивны), время в записи ставит clock.Now()
// внутри Flush. Тик-флаш идёт в контексте WithoutCancel — отмену
// shutdown'а посреди записи переживает и завершается (частичный флаш
// хуже целого), ошибки идут в OnError, цикл продолжает тикать.
func (k *Keeper) Run(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	k.mu.Lock()
	k.cancel = cancel
	k.done = make(chan struct{})
	done := k.done
	k.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(k.interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := k.Flush(context.WithoutCancel(runCtx)); err != nil && k.OnError != nil {
					k.OnError(err)
				}
			}
		}
	}()
}

// Stop гасит тикер, дожидается его выхода и делает финальный Flush:
// статистика на момент останова в БД (потеря — не больше одного
// интервала, и только при крахе процесса — штатный shutdown теряет
// ноль). Повторный Stop — идемпотентен (тикер уже погашен, остаётся
// финальный флаш).
func (k *Keeper) Stop(ctx context.Context) error {
	k.mu.Lock()
	cancel, done := k.cancel, k.done
	k.cancel, k.done = nil, nil
	k.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return k.Flush(ctx)
}
