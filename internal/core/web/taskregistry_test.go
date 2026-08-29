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

package web

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/testutil"
)

// newTestRegistry — реестр на часах, управляемых тестом: EMA и троттлинг
// лога детерминированы. workers — лимит параллелизма.
func newTestRegistry(t *testing.T, workers int) (*TaskRegistry, *testutil.ManualClock) {
	t.Helper()
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	return NewTaskRegistry(workers, clock), clock
}

// awaitState опрашивает задачу, пока не увидит want (или таймаут).
func awaitState(t *testing.T, r *TaskRegistry, id, want string) TaskSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		task, ok := r.Get(id)
		if !ok {
			t.Fatalf("задача %s пропала из реестра", id)
		}
		snap := task.Snapshot()
		if snap.State == want {
			return snap
		}
		time.Sleep(time.Millisecond)
	}
	task, _ := r.Get(id)
	t.Fatalf("задача %s не перешла в %s (сейчас %s)", id, want, task.Snapshot().State)
	return TaskSnapshot{}
}

func TestTaskRegistrySuccessAndSnapshot(t *testing.T) {
	r, clock := newTestRegistry(t, 2)
	started := make(chan struct{})
	var sawCurrent string
	id, err := r.Start("sync", "debian", func(ctx context.Context, p Progress) error {
		close(started)
		p.Update("scan", "dists/stable", 100, 1000)
		clock.Advance(600 * time.Millisecond)
		p.Update("scan", "dists/stable/Release", 500, 1000)
		snap := p.(*taskProgress).task.Snapshot()
		sawCurrent = snap.Current
		return nil
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-started
	snap := awaitState(t, r, id, taskSucceeded)
	if snap.State != taskSucceeded {
		t.Fatalf("state = %s", snap.State)
	}
	if snap.Error != "" {
		t.Errorf("error = %q", snap.Error)
	}
	if !snap.FinishedAt.IsZero() && snap.FinishedAt.Equal(snap.StartedAt) {
		t.Error("finishedAt не сдвинут")
	}
	if sawCurrent != "dists/stable/Release" {
		t.Errorf("current воркера = %q", sawCurrent)
	}
	if snap.Percent != 50 {
		t.Errorf("percent = %f, хочу 50", snap.Percent)
	}
	if len(snap.Logs) == 0 {
		t.Error("лог пуст")
	}
}

func TestTaskRegistryFailed(t *testing.T) {
	r, _ := newTestRegistry(t, 1)
	boom := errors.New("upstream упал")
	id, err := r.Start("sync", "fedora", func(ctx context.Context, p Progress) error {
		p.Log("стартую")
		return boom
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := awaitState(t, r, id, taskFailed)
	if snap.State != taskFailed {
		t.Fatalf("state = %s", snap.State)
	}
	if snap.Error != boom.Error() {
		t.Errorf("error = %q, хочу %q", snap.Error, boom.Error())
	}
}

func TestTaskRegistryDuplicateRejected(t *testing.T) {
	r, _ := newTestRegistry(t, 4)
	gate := make(chan struct{})
	id1, err := r.Start("sync", "debian", func(ctx context.Context, p Progress) error {
		p.Log("работаю")
		<-gate
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(gate) })
	awaitRunning(t, r, id1)
	if _, err := r.Start("sync", "debian", func(context.Context, Progress) error { return nil }); !errors.Is(err, ErrTaskDuplicate) {
		t.Fatalf("дубль = %v, хочу ErrTaskDuplicate", err)
	}
	// Другой label того же kind — допустим.
	if _, err := r.Start("sync", "ubuntu", func(context.Context, Progress) error { return nil }); err != nil {
		t.Fatalf("другой label: %v", err)
	}
}

func TestTaskRegistryLimitRejected(t *testing.T) {
	r, _ := newTestRegistry(t, 2)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	for i := 0; i < 2; i++ {
		if _, err := r.Start("sync", "r"+string(rune('a'+i)), func(context.Context, Progress) error {
			<-gate
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Start("sync", "overflow", func(context.Context, Progress) error { return nil }); !errors.Is(err, ErrTaskLimit) {
		t.Fatalf("сверх лимита = %v, хочу ErrTaskLimit", err)
	}
}

func TestTaskRegistryParallelRuns(t *testing.T) {
	r, _ := newTestRegistry(t, 3)
	var wg sync.WaitGroup
	var concurrent atomic.Int64
	var maxConcurrent atomic.Int64
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	for i := range 3 {
		_, err := r.Start("sync", "p"+string(rune('a'+i)), func(context.Context, Progress) error {
			cur := concurrent.Add(1)
			for {
				old := maxConcurrent.Load()
				if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
					break
				}
			}
			<-gate
			concurrent.Add(-1)
			return nil
		})
		if err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		wg.Add(1)
	}
	// Даём горутинам стартовать.
	time.Sleep(50 * time.Millisecond)
	if got := maxConcurrent.Load(); got != 3 {
		t.Errorf("одновременных = %d, хочу 3 (семафор не пропускает параллель)", got)
	}
}

func TestTaskRegistryCancelOnShutdown(t *testing.T) {
	r, _ := newTestRegistry(t, 1)
	cancelled := make(chan struct{})
	id, err := r.Start("sync", "debian", func(ctx context.Context, p Progress) error {
		p.Log("работаю")
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	awaitRunning(t, r, id)
	waitCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.WaitAll(waitCtx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitAll: %v", err)
	}
	<-cancelled
	snap := awaitState(t, r, id, taskFailed)
	if snap.State != taskFailed {
		t.Fatalf("state = %s", snap.State)
	}
	if !logsContain(snap.Logs, "задача отменена при остановке сервиса") {
		t.Errorf("лог отмены не записан: %v", snap.Logs)
	}
}

func TestTaskRegistryWaitAllSucceedsWhenIdle(t *testing.T) {
	r, _ := newTestRegistry(t, 2)
	if err := r.WaitAll(context.Background()); err != nil {
		t.Fatalf("WaitAll без задач: %v", err)
	}
}

func TestTaskRegistryWaitAllWaitsForCompletion(t *testing.T) {
	r, _ := newTestRegistry(t, 1)
	done := make(chan struct{})
	id, err := r.Start("sync", "debian", func(ctx context.Context, p Progress) error {
		<-done
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	awaitRunning(t, r, id)
	close(done)
	if err := r.WaitAll(context.Background()); err != nil {
		t.Fatalf("WaitAll: %v", err)
	}
	if snap, _ := r.Get(id); snap.Snapshot().State != taskSucceeded {
		t.Errorf("после WaitAll задача не succeeded")
	}
}

func TestTaskRegistryWaitAllTimeout(t *testing.T) {
	r, _ := newTestRegistry(t, 1)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	if _, err := r.Start("sync", "debian", func(ctx context.Context, p Progress) error {
		<-gate
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.WaitAll(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitAll таймаут = %v, хочу DeadlineExceeded", err)
	}
}

func TestTaskRegistrySlotFreedAfterCompletion(t *testing.T) {
	r, _ := newTestRegistry(t, 1)
	id, err := r.Start("sync", "debian", func(context.Context, Progress) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	awaitState(t, r, id, taskSucceeded)
	// Слот освобождён — новый запуск того же (kind,label) проходит.
	if _, err := r.Start("sync", "debian", func(context.Context, Progress) error { return nil }); err != nil {
		t.Fatalf("перезапуск после завершения: %v", err)
	}
}

func TestTaskRegistrySnapshotsOrderAndRingBuffer(t *testing.T) {
	r, clock := newTestRegistry(t, 3)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	id1, _ := r.Start("sync", "a", func(ctx context.Context, p Progress) error {
		<-gate
		return nil
	})
	awaitRunning(t, r, id1)
	clock.Advance(time.Millisecond)
	id2, _ := r.Start("sync", "b", func(context.Context, Progress) error { return nil })
	awaitState(t, r, id2, taskSucceeded)
	clock.Advance(time.Millisecond)

	// Кольцевой буфер: 60 строк, хранятся последние 50.
	ringID, _ := r.Start("test", "ring", func(ctx context.Context, p Progress) error {
		for i := range 60 {
			p.Log("line-" + itoa(i))
			clock.Advance(time.Microsecond)
		}
		return nil
	})
	awaitState(t, r, ringID, taskSucceeded)
	task, _ := r.Get(ringID)
	snap := task.Snapshot()
	if len(snap.Logs) != maxTaskLogs {
		t.Fatalf("логов = %d, хочу %d", len(snap.Logs), maxTaskLogs)
	}
	// 60 пользовательских строк + 1 строка успеха = 61; кольцо хранит
	// последние 50: line-11..line-59 + «задача завершена успешно».
	if snap.Logs[0] != "line-11" {
		t.Errorf("первая строка буфера = %q, хочу line-11", snap.Logs[0])
	}
	if snap.Logs[len(snap.Logs)-1] != "задача завершена успешно" {
		t.Errorf("последняя строка = %q, хочу строку успеха", snap.Logs[len(snap.Logs)-1])
	}

	snaps := r.Snapshots()
	if len(snaps) != 3 {
		t.Fatalf("снимков = %d, хочу 3", len(snaps))
	}
	// Активная задача (id1) — первой по времени старта.
	if snaps[0].ID != id1 {
		t.Errorf("первый снимок = %s, хочу активную %s", snaps[0].ID, id1)
	}
}

func TestTaskRegistryThrottleAutoLogs(t *testing.T) {
	r, clock := newTestRegistry(t, 1)
	id, _ := r.Start("test", "throttle", func(ctx context.Context, p Progress) error {
		// Три Update подряд без сдвига часов — троттлинг оставляет
		// только одну автоматическую строку.
		p.Update("phase", "f1", 1, 100)
		p.Update("phase", "f2", 2, 100)
		p.Update("phase", "f3", 3, 100)
		return nil
	})
	awaitState(t, r, id, taskSucceeded)
	task, _ := r.Get(id)
	snap := task.Snapshot()
	autoCount := 0
	for _, l := range snap.Logs {
		if contains(l, "[phase]") {
			autoCount++
		}
	}
	if autoCount != 1 {
		t.Errorf("автоматических строк = %d, хочу 1 (троттлинг 500мс)", autoCount)
	}
	clock.Advance(600 * time.Millisecond)
}

// awaitRunning ждёт, пока задача не станет running (воркер стартовал).
func awaitRunning(t *testing.T, r *TaskRegistry, id string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		task, ok := r.Get(id)
		if ok && task.State() == taskRunning {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("задача %s не стала running", id)
}

// contains — локальный strings.Contains (без импорта ради одной строки).
func contains(s string, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

// logsContain сообщает, есть ли подстрока в любой строке среза.
func logsContain(logs []string, sub string) bool {
	for _, l := range logs {
		if contains(l, sub) {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// itoa — локальный strconv.Itoa (без импорта ради одной строки).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Паника внутри задачи — StateFailed с "panic" в причине, реестр и
// процесс живут (аудит 2026-08-27: паника фоновой задачи роняла сервер).
func TestTaskRegistryPanicRecovery(t *testing.T) {
	r, _ := newTestRegistry(t, 2)
	id, err := r.Start("reindex", "boom", func(context.Context, Progress) error {
		panic("бум в генерации индексов")
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := awaitState(t, r, id, taskFailed)
	if !contains(snap.Error, "panic") || !contains(snap.Error, "бум") {
		t.Errorf("error = %q, хочу упоминание panic и причины", snap.Error)
	}
	// Реестр жив: следующая задача выполняется нормально.
	id2, err := r.Start("reindex", "ok", func(context.Context, Progress) error { return nil })
	if err != nil {
		t.Fatalf("Start после паники: %v", err)
	}
	awaitState(t, r, id2, taskSucceeded)
}

// История ограничена: 2000 задач → Snapshots не больше 1000, старейшие
// завершённые выпадают (аудит 2026-08-27: задачи никогда не чистились).
func TestTaskRegistryHistoryBounded(t *testing.T) {
	r, _ := newTestRegistry(t, 2)
	for i := range 2000 {
		id, err := r.Start("sync", "b"+string(rune('a'+i%26))+strconv.Itoa(i), func(context.Context, Progress) error { return nil })
		if err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		awaitState(t, r, id, taskSucceeded)
	}
	if snaps := r.Snapshots(); len(snaps) > maxTaskHistory {
		t.Fatalf("снимков = %d, потолок %d", len(snaps), maxTaskHistory)
	}
}

func TestNewTaskRegistryDefaults(t *testing.T) {
	// workers <= 0 → 1; nil clock → системный (не паникует).
	r := NewTaskRegistry(0, nil)
	if _, err := r.Start("t", "x", func(context.Context, Progress) error { return nil }); err != nil {
		t.Fatalf("Start с дефолтным лимитом: %v", err)
	}
	_ = r.WaitAll(context.Background())
}

func TestNewTaskIDUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		id := newTaskID("sync")
		if id == "" || !contains(id, "sync-") {
			t.Fatalf("неверный формат id: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("неуникальный id: %q", id)
		}
		seen[id] = struct{}{}
	}
}
