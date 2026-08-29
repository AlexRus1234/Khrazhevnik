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

// Реестр фоновых задач сервисa: in-memory map + горутины sync/зеркала/
// publish. Не персиститится (docs/ARCHITECTURE.md §3): персистентное
// состояние sync-задач (sync_jobs) пишут сами воркеры зеркал; реестр —
// только про живые задачи и их снимки для поллинга админкой.
//
// Контролирует параллелизм (семафор до N = mirror.workers) и запрещает
// одновременный запуск двух задач с одинаковым (kind, label): клиент
// получает 409 и может polled уже бегущую. Сверх N — 429.

package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"khrazhevnik/internal/core/port"
)

// Состояния задачи (строки попадают в JSON-снимок как есть).
const (
	taskRunning   = "running"
	taskSucceeded = "succeeded"
	taskFailed    = "failed"
)

// maxTaskLogs — размер кольцевого буфера лога задачи: последние 50 строк
// (docs/SPECIFICATION.md §REST API, требование сессии 09).
const maxTaskLogs = 50

// maxTaskHistory — потолок истории задач в реестре: старейшие
// завершённые выпадают из Snapshots, бегущие не трогаются (аудит
// 2026-08-27: задачи никогда не чистились — медленный рост памяти).
const maxTaskHistory = 1000

// minLogInterval — минимальный интервал между автоматическими строками
// лога из Update: поток прогресса не заливает буфер, оператор видит
// осмысленные кадры (2 Гц, как в lentovodec).
const minLogInterval = 500 * time.Millisecond

// ErrTaskDuplicate — задача с тем же (kind, label) уже бегущая (409).
var ErrTaskDuplicate = errors.New("task already running")

// ErrTaskLimit — исчерпан лимит параллельных задач (429).
var ErrTaskLimit = errors.New("task limit reached")

// Progress — репортёр прогресса фоновой задачи, передаваемый в fn.
// Тонкий и намеренно не знает о Task: воркеры зеркала/publish пишут
// снимки, не трогая состояние реестра.
type Progress interface {
	// Update публикует кадр прогресса; автоматическая строка лога
	// добавляется не чаще minLogInterval, скорость сглаживается EMA.
	Update(phase, current string, processed, total int64)
	// Log добавляет строку в кольцевой буфер без троттлинга — для
	// событий, которые оператор обязан увидеть сразу (ошибки, этапы).
	Log(line string)
}

// TaskSnapshot — неизменяемый снимок задачи для JSON-ответа поллинга
// (GET /api/v1/tasks, GET /api/v1/tasks/{id}).
type TaskSnapshot struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Label     string   `json:"label"`
	State     string   `json:"state"`
	Phase     string   `json:"phase"`
	Current   string   `json:"current"`
	Processed int64    `json:"processed"`
	Total     int64    `json:"total"`
	Percent   float64  `json:"percent"`
	SpeedBps  float64  `json:"speed_bps"`
	Logs      []string `json:"logs"`
	// Error — текст ошибки задачи (errText). РЕШЕНИЕ (сессия 25, аудит
	// 2026-08-27): отдаём как есть — оба эндпоинта задач admin-only, а
	// оператору нужна причина без выуживания её из логов сервера.
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// Task — живая фоновая задача. Снимок копируется под мьютексом, поэтому
// поллеры получают консистентный кадр без гонок с воркером.
type Task struct {
	ID    string
	Kind  string
	Label string

	mu         sync.Mutex
	state      string
	phase      string
	current    string
	processed  int64
	total      int64
	errText    string
	logs       []string
	lastLogAt  time.Time
	lastSample time.Time
	lastBytes  int64
	speedBps   float64
	startedAt  time.Time
	finishedAt time.Time
}

// Snapshot возвращает неизменяемый снимок прогресса задачи.
func (t *Task) Snapshot() TaskSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	var percent float64
	if t.total > 0 {
		percent = float64(t.processed) / float64(t.total) * 100
		if percent > 100 {
			percent = 100
		}
	}
	logs := make([]string, len(t.logs))
	copy(logs, t.logs)
	return TaskSnapshot{
		ID: t.ID, Kind: t.Kind, Label: t.Label, State: t.state,
		Phase: t.phase, Current: t.current,
		Processed: t.processed, Total: t.total,
		Percent: percent, SpeedBps: t.speedBps,
		Logs: logs, Error: t.errText,
		StartedAt: t.startedAt, FinishedAt: t.finishedAt,
	}
}

// State возвращает текущее состояние без полной копии (для фильтров).
func (t *Task) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// update применяет кадр прогресса; скорость — EMA по дельте байт,
// автоматическая строка лога троттлится minLogInterval.
func (t *Task) update(phase, current string, processed, total int64, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != taskRunning {
		return
	}
	dt := now.Sub(t.lastSample)
	if dt > 0 && processed >= t.lastBytes {
		inst := float64(processed-t.lastBytes) / dt.Seconds()
		if t.speedBps == 0 {
			t.speedBps = inst
		} else {
			t.speedBps = 0.5*t.speedBps + 0.5*inst // EMA, alpha=0.5
		}
	}
	t.lastSample, t.lastBytes = now, processed
	t.phase, t.current, t.processed, t.total = phase, current, processed, total
	if now.Sub(t.lastLogAt) >= minLogInterval {
		t.appendLogLocked(fmt.Sprintf("[%s] %s (%s / %s)",
			phase, current, humanBytes(processed), humanBytes(total)))
		t.lastLogAt = now
	}
}

// logLine добавляет строку без троттлинга (события оператора).
func (t *Task) logLine(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.appendLogLocked(line)
}

// finishSuccess фиксирует успешное завершение.
func (t *Task) finishSuccess(now time.Time) {
	t.mu.Lock()
	if t.state != taskRunning {
		t.mu.Unlock()
		return
	}
	t.state = taskSucceeded
	t.finishedAt = now
	t.appendLogLocked("задача завершена успешно")
	t.mu.Unlock()
}

// finishError фиксирует завершение с ошибкой (включая отмену ctx).
func (t *Task) finishError(err error, now time.Time) {
	t.mu.Lock()
	if t.state != taskRunning {
		t.mu.Unlock()
		return
	}
	t.state = taskFailed
	t.finishedAt = now
	t.errText = err.Error()
	t.appendLogLocked("задача завершена ошибкой: " + t.errText)
	t.mu.Unlock()
}

// appendLogLocked добавляет строку в кольцевой буфер. Под мьютексом.
func (t *Task) appendLogLocked(line string) {
	t.logs = append(t.logs, line)
	if len(t.logs) > maxTaskLogs {
		t.logs = t.logs[len(t.logs)-maxTaskLogs:]
	}
}

// taskProgress — Progress, пишущий в Task; берёт время из port.Clock,
// чтобы тайминги EMA и троттлинга были детерминированы в тестах.
type taskProgress struct {
	task  *Task
	clock port.Clock
}

// Update публикует кадр прогресса.
func (p *taskProgress) Update(phase, current string, processed, total int64) {
	p.task.update(phase, current, processed, total, p.clock.Now())
}

// Log добавляет строку без троттлинга.
func (p *taskProgress) Log(line string) { p.task.logLine(line) }

// TaskRegistry — общий реестр фоновых задач сервиса. Параллелизм —
// семафором до N (mirror.workers); дубль (kind,label) — 409; сверх N —
// 429. Shutdown — отмена ctx-дерева: все воркеры получают отмену,
// WaitAll ждёт их завершения в рамках таймаута каскада (server.go).
type TaskRegistry struct {
	mu       sync.Mutex
	tasks    map[string]*Task
	active   map[string]*Task // ключ kind|label → бегущая задача
	sem      chan struct{}    // семафор параллелизма (буфер N)
	wg       sync.WaitGroup
	clock    port.Clock
	shutdown context.Context
	cancel   context.CancelFunc
}

// NewTaskRegistry создаёт реестр с лимитом workers параллельных задач.
// workers <= 0 заменяется на 1: нулевой лимит означал бы мёртвый реестр.
func NewTaskRegistry(workers int, clock port.Clock) *TaskRegistry {
	if workers < 1 {
		workers = 1
	}
	if clock == nil {
		clock = systemWebClock{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskRegistry{
		tasks:    make(map[string]*Task),
		active:   make(map[string]*Task),
		sem:      make(chan struct{}, workers),
		clock:    clock,
		shutdown: ctx,
		cancel:   cancel,
	}
}

// Start регистрирует задачу и запускает fn в фоновой горутине с
// производным от shutdown контекстом. Лимит параллелизма и дубль
// проверяются атомарно под mu. fn завершает задачу через возвращённую
// ошибку: nil → succeeded, иначе failed; отмена ctx — failed.
func (r *TaskRegistry) Start(kind, label string, fn func(ctx context.Context, p Progress) error) (string, error) {
	r.mu.Lock()
	key := kind + "|" + label
	if _, dup := r.active[key]; dup {
		r.mu.Unlock()
		return "", ErrTaskDuplicate
	}
	select {
	case r.sem <- struct{}{}:
	default:
		r.mu.Unlock()
		return "", ErrTaskLimit
	}
	task := &Task{
		ID:        newTaskID(kind),
		Kind:      kind,
		Label:     label,
		state:     taskRunning,
		startedAt: r.clock.Now(),
	}
	r.tasks[task.ID] = task
	r.evictHistoryLocked()
	r.active[key] = task
	r.mu.Unlock()

	r.launch(task, fn)
	return task.ID, nil
}

// evictHistoryLocked держит историю задач в пределах maxTaskHistory:
// старейшая завершённая выпадает (running трогать нельзя — на них
// смотрят поллеры и active-индекс). Вызывается под r.mu после вставки.
func (r *TaskRegistry) evictHistoryLocked() {
	for len(r.tasks) > maxTaskHistory {
		var oldest *Task
		for _, t := range r.tasks {
			if t.State() == taskRunning {
				continue
			}
			if oldest == nil || t.startedAt.Before(oldest.startedAt) ||
				(t.startedAt.Equal(oldest.startedAt) && t.ID < oldest.ID) {
				oldest = t
			}
		}
		if oldest == nil {
			// все задачи бегущие — потолок временно превышен, чистить
			// нечего (workers ограничен, это не утечка)
			return
		}
		delete(r.tasks, oldest.ID)
	}
}

// launch запускает fn в фоновой горутине с производным ctx и
// контролируемым освобождением семафора и active-слота.
func (r *TaskRegistry) launch(task *Task, fn func(ctx context.Context, p Progress) error) {
	ctx, cancel := context.WithCancel(r.shutdown)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		defer func() {
			<-r.sem
			r.mu.Lock()
			delete(r.active, task.Kind+"|"+task.Label)
			r.mu.Unlock()
		}()
		p := &taskProgress{task: task, clock: r.clock}
		err := r.runTask(task, p, fn, ctx)
		if err == nil {
			task.finishSuccess(r.clock.Now())
			return
		}
		// Отмена shutdown'ом — отдельная диагностика в логе задачи.
		if errors.Is(err, context.Canceled) && r.shutdown.Err() != nil {
			task.logLine("задача отменена при остановке сервиса")
		}
		task.finishError(err, r.clock.Now())
	}()
}

// runTask изолирует panic функции задачи: паника фоновой задачи — это
// failed-задача с причиной "panic", а не смерть процесса (аудит
// 2026-08-27: recover отсутствовал во всём прод-коде — одна паника в
// генерации индексов укладывала сервер).
func (r *TaskRegistry) runTask(task *Task, p Progress, fn func(ctx context.Context, p Progress) error, ctx context.Context) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Default().Error("фоновой задачи: паника",
				"kind", task.Kind, "label", task.Label, "task_id", task.ID,
				"panic", rec, "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return fn(ctx, p)
}

// Get возвращает задачу по идентификатору.
func (r *TaskRegistry) Get(id string) (*Task, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tasks[id]
	return t, ok
}

// Snapshots отдаёт снимки всех задач, активные первыми (по времени
// старта), затем завершённые — стабильный порядок для поллинга списком.
func (r *TaskRegistry) Snapshots() []TaskSnapshot {
	r.mu.Lock()
	tasks := make([]*Task, 0, len(r.tasks))
	for _, t := range r.tasks {
		tasks = append(tasks, t)
	}
	r.mu.Unlock()
	sort.SliceStable(tasks, func(i, j int) bool {
		ti, tj := tasks[i].startedAt, tasks[j].startedAt
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return tasks[i].ID < tasks[j].ID
	})
	out := make([]TaskSnapshot, len(tasks))
	for i, t := range tasks {
		out[i] = t.Snapshot()
	}
	return out
}

// HasActive сообщает, есть ли хоть одна бегущая задача.
func (r *TaskRegistry) HasActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active) > 0
}

// WaitAll отменяет ctx-дерево задач и ждёт завершения всех воркеров
// или отмены ctx (таймаут накладывает вызывающий — server.go).
func (r *TaskRegistry) WaitAll(ctx context.Context) error {
	r.cancel()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// newTaskID — идентификатор вида "<kind>-<8hex>" из crypto/rand; при
// отказе энтропии — по таймеру (уникальность важнее случайности).
func newTaskID(kind string) string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s-%08d", kind, time.Now().UnixNano()%1e8)
	}
	return kind + "-" + hex.EncodeToString(buf)
}

// humanBytes — компактное человекочитаемое число байт для лога задачи.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// systemWebClock — port.Clock поверх time.Now: реестр без явного Clock
// (тесты подменяют) получает системную реализацию, не дёргая wire.
type systemWebClock struct{}

// Now возвращает текущее время.
func (systemWebClock) Now() time.Time { return time.Now() }
