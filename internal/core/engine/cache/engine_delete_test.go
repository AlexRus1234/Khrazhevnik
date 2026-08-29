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

// Фоновые удаления прошлых версий mutable-объектов (аудит 2026-08-27):
// параллелизм ограничен семафором, shutdown дожидается очередь.

package cache

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// gatedDeleteStorage — хранилище с блокируемым Delete: gate держит
// удаления открытыми, счётчики фиксируют текущий/пиковый параллелизм.
type gatedDeleteStorage struct {
	port.Storage
	gate     chan struct{}
	inflight atomic.Int64
	peak     atomic.Int64
}

func (s *gatedDeleteStorage) Delete(ctx context.Context, key string) error {
	n := s.inflight.Add(1)
	for {
		old := s.peak.Load()
		if n <= old || s.peak.CompareAndSwap(old, n) {
			break
		}
	}
	<-s.gate
	s.inflight.Add(-1)
	return s.Storage.Delete(ctx, key)
}

// TestDeleteInBackgroundBoundedAndDrained — всплеск фоновых удалений
// ограничен семафором (≤ deleteConcurrency), Drain дожидается всех
// (в т.ч. по отменённому таймауту — пока очередь не пуста).
func TestDeleteInBackgroundBoundedAndDrained(t *testing.T) {
	clock := testutil.NewManualClock(testStart)
	base := testutil.NewFakeStorage(clock)
	s := &gatedDeleteStorage{Storage: base, gate: make(chan struct{})}
	e := New(s, testutil.NewFakeObjectIndex(), nil, clock, Config{}, nil)

	for i := range 8 {
		e.deleteInBackground(&domain.ObjectMeta{Key: "cache/t/obj" + string(rune('a'+i))})
	}
	// минимум одно удаление зашло в Delete и встало на gate
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.inflight.Load() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if s.inflight.Load() == 0 {
		t.Fatal("ни одно удаление не дошло до хранилища")
	}

	// пока gate закрыт, очередь не пуста: короткий Drain обязан
	// вернуться по таймауту
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if err := e.DrainBackgroundDeletes(ctx); err == nil {
		t.Error("Drain при незакрытом gate вернулся без ожидания")
	}
	cancel()

	close(s.gate)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := e.DrainBackgroundDeletes(ctx2); err != nil {
		t.Fatalf("Drain после открытия gate: %v", err)
	}
	if peak := s.peak.Load(); peak > deleteConcurrency {
		t.Errorf("пиковый параллелизм удалений %d, потолок %d", peak, deleteConcurrency)
	}
	if s.inflight.Load() != 0 {
		t.Errorf("удаления не дошли до конца: %d в полёте", s.inflight.Load())
	}
}

// panickyDeleteStorage — Delete паникует: recover движка обязан
// изолировать сбой драйвера, не оставив счётчики несбалансированными
// (иначе DrainBackgroundDeletes зависал бы на shutdown навечно).
type panickyDeleteStorage struct {
	port.Storage
}

func (s *panickyDeleteStorage) Delete(context.Context, string) error {
	panic("storage взорвался")
}

// TestDeleteInBackgroundPanicRecovered — паника storage.Delete
// изолируется: счётчики сбалансированы (Drain возвращает nil), паника
// посчитана в метрике, процесс жив.
func TestDeleteInBackgroundPanicRecovered(t *testing.T) {
	clock := testutil.NewManualClock(testStart)
	m := metrics.NewCache()
	e := New(&panickyDeleteStorage{Storage: testutil.NewFakeStorage(clock)}, testutil.NewFakeObjectIndex(), nil, clock, Config{}, m)
	e.deleteInBackground(&domain.ObjectMeta{Key: "cache/t/boom"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.DrainBackgroundDeletes(ctx); err != nil {
		t.Fatalf("Drain после паники удаления: %v", err)
	}
	if got := m.BackgroundPanics.Load(); got != 1 {
		t.Fatalf("счётчик фоновых паник = %d, хочу 1", got)
	}
	// очередь жива: следующее удаление (штатное) проходит
	e.deleteInBackground(&domain.ObjectMeta{Key: "cache/t/ok"})
	if err := e.DrainBackgroundDeletes(ctx); err != nil {
		t.Fatalf("Drain штатного удаления после паники: %v", err)
	}
}

// TestDrainBackgroundDeletesEmpty — Drain на пустой очереди возвращает
// nil немедленно (shutdown без замен не должен ждать).
func TestDrainBackgroundDeletesEmpty(t *testing.T) {
	clock := testutil.NewManualClock(testStart)
	e := New(testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(), nil, clock, Config{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.DrainBackgroundDeletes(ctx); err != nil {
		t.Fatalf("Drain пустой очереди: %v", err)
	}
}
