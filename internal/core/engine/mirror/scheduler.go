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

// Scheduler — фоновый планировщик зеркал: per-remote тикер с джиттером.
// Один планировщик на процесс; remotes с mode=mirror и SyncInterval>0
// синкаются автоматически. mode=proxy — только ручной sync через API.
// При старте не синкает всё сразу: к интервалу каждого remote добавляется
// случайный джиттер (port.Rand), чтобы раскидать нагрузку. Удалённый
// или выключенный remote — стоп его тикера.

package mirror

import (
	"context"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Scheduler управляет per-remote тикерами.
type Scheduler struct {
	engine  *Engine
	remotes port.RemoteStore
	rand    port.Rand
	clock   port.Clock
	jitter  time.Duration

	mu       sync.Mutex
	runners  map[int64]*runner
	shutdown context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewScheduler создаёт планировщик. jitter — разброс интервала (±jitter),
// берётся из config.Mirror.IntervalJitter. rand — для джиттера (в
// тестах FixedRand даёт детерминированные интервалы).
func NewScheduler(engine *Engine, remotes port.RemoteStore, rand port.Rand, clock port.Clock, jitter time.Duration) *Scheduler {
	if rand == nil {
		rand = noopRand{}
	}
	if clock == nil {
		clock = systemClock{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		engine: engine, remotes: remotes, rand: rand, clock: clock, jitter: jitter,
		runners:  map[int64]*runner{},
		shutdown: ctx, cancel: cancel,
	}
}

// Start поднимает тикеры для всех подходящих remotes (mode=mirror,
// enabled, SyncInterval>0). Повторно вызывающие безопасны: новые
// remotes подхватываются, убранные — стопаются.
func (s *Scheduler) Start(ctx context.Context) error {
	rs, err := s.remotes.Remotes(ctx)
	if err != nil {
		return err
	}
	for _, r := range rs {
		s.startRunner(r)
	}
	return nil
}

// startRunner поднимает тикер для remote, если он подходит (mirror,
// enabled, SyncInterval>0). Идемпотентно: повторный вызов для бегущего
// runner — no-op; выключенный/удалённый remote — стоп его runner.
func (s *Scheduler) startRunner(r domain.Remote) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.runners[r.ID]; ok {
		if !shouldRun(r) {
			existing.stop()
			delete(s.runners, r.ID)
		}
		return
	}
	if !shouldRun(r) {
		return
	}
	rn := &runner{
		sched:  s,
		remote: r,
		stopCh: make(chan struct{}),
	}
	s.runners[r.ID] = rn
	s.wg.Add(1)
	go rn.run()
}

// runner — per-remote тикер.
type runner struct {
	sched  *Scheduler
	remote domain.Remote
	stopCh chan struct{}
}

// run крутит тикер: первый тик сразу (по джиттеру), затем SyncInterval.
func (rn *runner) run() {
	defer rn.sched.wg.Done()
	// первый тик — со сдвигом [0, jitter], чтобы раскидать старт
	first := rn.sched.nextInterval(rn.remote)
	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-rn.stopCh:
			return
		case <-rn.sched.shutdown.Done():
			return
		case <-timer.C:
			// снеп remote из БД: настройки могли поменяться
			r, err := rn.sched.remotes.Remote(rn.sched.shutdown, rn.remote.ID)
			if err != nil || !shouldRun(r) {
				return
			}
			ctx, cancel := context.WithCancel(rn.sched.shutdown)
			_ = rn.sched.engine.Sync(ctx, r, noopProgress{})
			cancel()
			// следующий тик — SyncInterval ± jitter
			timer.Reset(rn.sched.nextInterval(r))
		}
	}
}

// nextInterval возвращает SyncInterval ± jitter (джиттер ∈ [0, jitter],
// сложение только: интервал — минимум, jitter — разброс вправо).
func (s *Scheduler) nextInterval(r domain.Remote) time.Duration {
	base := r.SyncInterval
	if base <= 0 {
		base = time.Minute
	}
	if s.jitter <= 0 {
		return base
	}
	j := s.rand.Int64(int64(s.jitter))
	return base + time.Duration(j)
}

// stop останавливает runner; ждёт завершения горутины.
func (rn *runner) stop() {
	close(rn.stopCh)
}

// Stop гасит планировщик: отменяет shutdown-ctx, ждёт всех runner'ов.
// Вызывается из graceful shutdown сервера.
func (s *Scheduler) Stop(ctx context.Context) error {
	s.mu.Lock()
	for _, rn := range s.runners {
		rn.stop()
	}
	s.mu.Unlock()
	s.cancel()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// shouldRun — критерий авто-sync: mirror, enabled, положительный интервал.
func shouldRun(r domain.Remote) bool {
	return r.Mode == domain.ModeMirror && r.Enabled && r.SyncInterval > 0
}

// noopRand — заглушка для Scheduler без реального port.Rand (тесты
// подменяют; прод идёт через uuidRand в wire).
type noopRand struct{}

func (noopRand) UUID4() (string, error) { return "00000000-0000-4000-8000-000000000000", nil }
func (noopRand) Int64(int64) int64      { return 0 }
