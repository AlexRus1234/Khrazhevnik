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

// Scheduler — фоновый планировщик зеркал: reconcile-цикл (тик + notify).
// Один планировщик на процесс. Каждый цикл сверяет живых runner'ов с
// БД: старт недостающих, стоп исчезнувших/выключенных, перезапуск
// умерших с backoff. Notify будит цикл немедленно — admin-CRUD remotes
// и ручной sync подхватываются без рестарта процесса. Ошибка БД не
// убивает цикл: retry на следующем тике. Runner'ы общаются со stop
// через sync.Once и done-канал: повторный Stop не паникует, стоп
// remote останавливает идущий sync, двойных runner'ов не бывает.

package mirror

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

const (
	// reconcileInterval — период сверки живых runner'ов с БД.
	reconcileInterval = 30 * time.Second
	// maxRunnerBackoff — потолок паузы перед перезапуском умершего
	// runner'а: экспоненциальный рост от тика, чтобы умирающий на
	// каждом тике runner не молотил впустую вечно.
	maxRunnerBackoff = 10 * time.Minute
)

// Scheduler управляет per-remote runner'ами через reconcile-цикл.
type Scheduler struct {
	engine  *Engine
	remotes port.RemoteStore
	rand    port.Rand
	clock   port.Clock
	jitter  time.Duration

	// ErrorHook — опциональный репортёр ошибок фонового цикла (лог
	// в wire): reconcile и смерти runner'ов возвращать некому.
	ErrorHook func(error)

	mu        sync.Mutex
	runners   map[int64]*runner
	deaths    map[int64]int       // подряд умерших runner'ов (backoff)
	lastDeath map[int64]time.Time // момент последней смерти
	shutdown  context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	notify    chan struct{}
	stopOnce  sync.Once
	// tick — период reconcile; константа в проде, тесты укорачивают.
	tick time.Duration
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
		runners:   map[int64]*runner{},
		deaths:    map[int64]int{},
		lastDeath: map[int64]time.Time{},
		shutdown:  ctx, cancel: cancel,
		notify: make(chan struct{}, 1),
		tick:   reconcileInterval,
	}
}

// Start поднимает reconcile-цикл. Ошибки БД на старте не фатальны:
// первый reconcile идёт сразу, сбойный — ретраится на следующем тике.
func (s *Scheduler) Start(_ context.Context) {
	s.wg.Add(1)
	go s.loop()
}

// loop — reconcile-цикл: сразу, затем по тику и по notify.
func (s *Scheduler) loop() {
	defer s.wg.Done()
	s.reconcile()
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-s.shutdown.Done():
			return
		case <-t.C:
			s.reconcile()
		case <-s.notify:
			s.reconcile()
		}
	}
}

// Notify будит reconcile немедленно: добавленный/включённый remote
// (admin-CRUD) и ручной sync не ждут тика. Буфер 1 + не блокируем:
// пропущенные уведомления догоняет следующий тик.
func (s *Scheduler) Notify() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// reconcile приводит живых runner'ов в соответствие с БД. Ошибка
// чтения — не смерть цикла: retry на следующем тике.
func (s *Scheduler) reconcile() {
	rs, err := s.remotes.Remotes(s.shutdown)
	if err != nil {
		s.reportError(err)
		return
	}
	wanted := make(map[int64]domain.Remote, len(rs))
	for _, r := range rs {
		if shouldRun(r) {
			wanted[r.ID] = r
		}
	}
	now := s.clock.Now()
	var toStop []*runner
	var toStart []domain.Remote
	s.mu.Lock()
	for id, rn := range s.runners {
		if _, ok := wanted[id]; !ok {
			toStop = append(toStop, rn)
			delete(s.runners, id)
		}
	}
	// Забвение backoff-состояния исчезнувших/выключенных remote: без
	// этого записи живут вечно, а пересозданный remote с тем же ID
	// наследовал бы чужой накопленный backoff.
	for id := range s.deaths {
		if _, ok := wanted[id]; !ok {
			delete(s.deaths, id)
			delete(s.lastDeath, id)
		}
	}
	// Страховка от расхождения карт (пишутся парно, но инвариант не
	// закреплён типом).
	for id := range s.lastDeath {
		if _, ok := wanted[id]; !ok {
			delete(s.lastDeath, id)
		}
	}
	for id, r := range wanted {
		if _, ok := s.runners[id]; ok {
			continue
		}
		if s.backoffLeftLocked(id, now) > 0 {
			continue
		}
		toStart = append(toStart, r)
	}
	s.mu.Unlock()
	// stop ждёт завершения горутины — вне мьютекса: exit-путь runner'а
	// берёт тот же мьютекс (forgetRunner).
	for _, rn := range toStop {
		rn.stop()
	}
	for _, r := range toStart {
		s.startRunner(r)
	}
}

// backoffLeftLocked — остаток паузы перед перезапуском после подряд
// смертей runner'а: первая смерть — рестарт на ближайшем тике,
// повторные — экспоненциально (тик, 2×тик, …, потолок). Под мьютексом.
func (s *Scheduler) backoffLeftLocked(id int64, now time.Time) time.Duration {
	d := s.deaths[id]
	if d <= 1 {
		return 0
	}
	b := s.tick
	for range d - 2 {
		b *= 2
		if b >= maxRunnerBackoff {
			return maxRunnerBackoff
		}
	}
	last, ok := s.lastDeath[id]
	if !ok {
		return 0
	}
	if left := b - now.Sub(last); left > 0 {
		return left
	}
	return 0
}

// startRunner поднимает runner для подходящего remote (mirror, enabled,
// SyncInterval>0). Идемпотентно: живой runner для того же ID — no-op
// (инвариант «не более одного runner'а на remote»).
func (s *Scheduler) startRunner(r domain.Remote) {
	s.mu.Lock()
	if _, ok := s.runners[r.ID]; ok {
		s.mu.Unlock()
		return
	}
	if !shouldRun(r) {
		s.mu.Unlock()
		return
	}
	rn := newRunner(s, r)
	s.runners[r.ID] = rn
	s.wg.Add(1)
	s.mu.Unlock()
	go rn.run()
}

// forgetRunner удаляет запись умершего runner'а; запись другого
// экземпляра (перезапущенного) не трогаем — гонка с reconcile.
func (s *Scheduler) forgetRunner(id int64, rn *runner) {
	s.mu.Lock()
	if cur, ok := s.runners[id]; ok && cur == rn {
		delete(s.runners, id)
	}
	s.mu.Unlock()
}

// runnerDied фиксирует смерть от ошибки: счётчик для backoff.
func (s *Scheduler) runnerDied(id int64, cause error) {
	s.mu.Lock()
	s.deaths[id]++
	s.lastDeath[id] = s.clock.Now()
	s.mu.Unlock()
	s.reportError(cause)
}

// runnerHealthy сбрасывает backoff: runner пережил тик sync.
func (s *Scheduler) runnerHealthy(id int64) {
	s.mu.Lock()
	delete(s.deaths, id)
	delete(s.lastDeath, id)
	s.mu.Unlock()
}

func (s *Scheduler) reportError(err error) {
	if err != nil && s.ErrorHook != nil {
		s.ErrorHook(err)
	}
}

// runner — per-remote тикер.
type runner struct {
	sched  *Scheduler
	remote domain.Remote
	// stopCtx — сигнал остановки конкретного runner'а; связывается с
	// ctx каждого sync через context.AfterFunc: стоп remote гасит
	// идущий sync. stopOnce — повторный stop не паникует.
	stopCtx    context.Context
	stopCancel context.CancelFunc
	stopOnce   sync.Once
	// done закрывается при выходе горутины: stop ждёт его, чтобы
	// перезапущенный runner не бежал параллельно с умирающим sync.
	done chan struct{}
}

// newRunner создаёт runner с собственным stop-контекстом.
func newRunner(s *Scheduler, r domain.Remote) *runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &runner{
		sched: s, remote: r,
		stopCtx: ctx, stopCancel: cancel,
		done: make(chan struct{}),
	}
}

// run крутит тикер: первый тик сразу (по джиттеру), затем SyncInterval.
func (rn *runner) run() {
	defer rn.sched.wg.Done()
	defer rn.sched.forgetRunner(rn.remote.ID, rn)
	defer close(rn.done)
	defer rn.stopCancel()
	first := rn.sched.nextInterval(rn.remote)
	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-rn.stopCtx.Done():
			return
		case <-rn.sched.shutdown.Done():
			return
		case <-timer.C:
			if !rn.tick() {
				return
			}
			timer.Reset(rn.sched.nextInterval(rn.remote))
		}
	}
}

// tick — один прогон sync; false — runner больше не нужен (умер от
// ошибки БД или remote выключили/удалили — reconcile разрулит).
func (rn *runner) tick() bool {
	if rn.sched.engine == nil {
		// деградация без движка (тесты): тикер жив, sync некому делать
		return true
	}
	// снеп remote из БД: настройки могли поменяться
	r, err := rn.sched.remotes.Remote(rn.sched.shutdown, rn.remote.ID)
	if err != nil {
		rn.sched.runnerDied(rn.remote.ID, err)
		return false
	}
	if !shouldRun(r) {
		return false
	}
	ctx, cancel := context.WithCancel(rn.sched.shutdown)
	defer cancel()
	// связка stopCtx с ctx: стоп remote гасит идущий sync
	stop := context.AfterFunc(rn.stopCtx, cancel)
	defer stop()
	// Паника sync изолируется: runner живёт (пересинк по интервалу),
	// причина уходит в ErrorHook (аудит 2026-08-27: тело runner'а —
	// фоновая горутина, паника роняла весь процесс). Обычные ошибки
	// sync уже записаны в sync_jobs движком.
	if err := rn.safeSync(ctx, r); err != nil {
		var pe *panicError
		if errors.As(err, &pe) {
			rn.sched.reportError(fmt.Errorf("sync %s: %w", r.Name, err))
		}
	}
	rn.sched.runnerHealthy(rn.remote.ID)
	return true
}

// safeSync запускает Sync, превращая панику в ошибку.
func (rn *runner) safeSync(ctx context.Context, r domain.Remote) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = &panicError{rec: rec}
		}
	}()
	return rn.sched.engine.Sync(ctx, r, noopProgress{})
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

// stop останавливает runner и ждёт завершения горутины (sync получает
// отмену через AfterFunc-связку и успевает записать финальный статус).
func (rn *runner) stop() {
	rn.stopOnce.Do(func() { rn.stopCancel() })
	<-rn.done
}

// Stop гасит планировщик: отменяет shutdown-ctx, ждёт цикл и всех
// runner'ов (с таймаутом ctx). Повторный вызов безопасен и дёшев:
// горутины уже дожаты первым.
func (s *Scheduler) Stop(ctx context.Context) error {
	s.stopOnce.Do(func() { s.cancel() })
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
