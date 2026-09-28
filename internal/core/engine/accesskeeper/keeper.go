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

// Package accesskeeper — фиксация обращений к объектам без записи в БД
// на горячем пути: Record копит (ключ → последнее время, счётчик) в
// памяти под мьютексом, одна горутина-тикер раз в интервал мёржит
// накопленное в object_access одной транзакцией (MergeAccess).
// Отдельный компонент рядом с движками, а не их часть: точки фиксации
// (публичный роутер репо :29202 и кеш-прокси HIT) не получают ни
// порта БД, ни горутин — синхронная запись на каждый GET была бы
// write-амплификацией. Прецедент — statskeeper (сессия 96), цена —
// потеря не больше одного интервала при крахе процесса (как ring-буфер
// транзакций сессии 99).
package accesskeeper

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// maxKeys — потолок карты накопления: защита памяти от сканера,
// перебирающего уникальные пути (каждый ключ + строка — сотни байт,
// 100k ключей ≈ десятки МиБ). Переполнение не вытесняет старое и не
// роняет запись: новые ключи не аккредитуются, счётчик dropped растёт.
const maxKeys = 100_000

// keySep разделяет scope и ключ объекта в составном ключе карты —
// склейка без разделителя путала бы (scope, key) разных пар
// («repo"+"x/y» и «repox"+"y»). Ноль невозможен в путях namespace'а.
const keySep = "\x00"

// acc — накопленное по одному объекту: время последнего обращения
// (unix-нано, MAX — гонка двух GET даёт большее) и число обращений.
type acc struct {
	unixNano int64
	hits     int64
}

// Keeper — накопитель обращений с фоновым батч-мёржем в AccessStore.
type Keeper struct {
	store    port.AccessStore
	clock    port.Clock
	interval time.Duration

	// OnError — колбэк ошибок тик-флашей (инжектится wire'ом, как
	// Scheduler.ErrorHook): сбой БД не гасит цикл, но и не теряется
	// молча.
	OnError func(error)

	// mu охраняет acc; dropped — атомик (читается метриками без
	// блокировки горячего пути).
	mu      sync.Mutex
	acc     map[string]acc
	dropped atomic.Int64

	// mu также охраняет cancel/done — поля жизненного цикла Run/Stop.
	cancel context.CancelFunc // nil до Run и после Stop
	done   chan struct{}      // закрытие = горутина-тикер вышла
}

// New собирает keeper'а поверх порта обращений; interval — период
// фонового мёржа (0 недопустим — отсекается wire'ом, тикер с нулевым
// интервалом паникует).
func New(store port.AccessStore, clock port.Clock, interval time.Duration) *Keeper {
	return &Keeper{store: store, clock: clock, interval: interval, acc: make(map[string]acc)}
}

// Record фиксирует обращение к объекту: O(1), без БД, без аллокации
// канала. Время берётся из port.Clock и только «вперёд» (MAX):
// откат часов назад не омолаживает объект для ретеншна.
func (k *Keeper) Record(scope, key string) {
	now := k.clock.Now().UnixNano()
	id := scope + keySep + key
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.acc[id]
	if !ok && len(k.acc) >= maxKeys {
		k.dropped.Add(1)
		return
	}
	if now > e.unixNano {
		e.unixNano = now
	}
	e.hits++
	k.acc[id] = e
}

// Flush отдаёт накопленное одной транзакцией MergeAccess. Карта
// свопается на пустую под мьютексом — Record с этого момента попадает
// в следующее окно, а не в отправляемый батч (иначе флаш мог бы
// «утащить» обращение, пришедшее во время записи). Пустая карта —
// no-op без похода в БД. Сбой БД возвращается вызывающему: тик-цикл
// его только логирует и продолжает тикать (батч теряется — та же цена
// окна, что и при крахе процесса).
func (k *Keeper) Flush(ctx context.Context) error {
	k.mu.Lock()
	cur := k.acc
	if len(cur) == 0 {
		k.mu.Unlock()
		return nil
	}
	k.acc = make(map[string]acc, len(cur))
	k.mu.Unlock()
	// Счётчик отброшенного — за окно флаша: диагностика «карта
	// переполнена именно сейчас», а не с начала жизни процесса.
	k.dropped.Store(0)

	rows := make([]domain.ObjectAccess, 0, len(cur))
	for id, e := range cur {
		scope, key, ok := strings.Cut(id, keySep)
		if !ok {
			continue // недостижимо: id всегда собран Record'ом
		}
		rows = append(rows, domain.ObjectAccess{
			Scope:      scope,
			Key:        key,
			LastAccess: time.Unix(0, e.unixNano),
			Hits:       e.hits,
		})
	}
	return k.store.MergeAccess(ctx, rows)
}

// Dropped — сколько обращений не аккредитовано из-за потолка карты
// (счётчик за текущее окно флаша) — для метрик и диагностики.
func (k *Keeper) Dropped() int64 { return k.dropped.Load() }

// Run запускает горутину-тикер: раз в interval — Flush. Тик-флаш идёт
// в контексте WithoutCancel — отмену shutdown'а посреди записи
// переживает и завершается (частичный батч хуже целого), ошибки идут в
// OnError, цикл продолжает тикать.
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

// Stop гасит тикер, дожидается его выхода и делает финальный Flush —
// обращения, накопленные после последнего тика, доезжают до БД
// штатным shutdown'ом (потеря остаётся только за крах процесса).
// Повторный Stop идемпотентен: тикер уже погашен, повторный финальный
// флаш видит пустую карту и не идёт в БД.
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
