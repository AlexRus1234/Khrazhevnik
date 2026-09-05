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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	mirrorengine "khrazhevnik/internal/core/engine/mirror"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// clock для тестов — фиксированный момент: всем движкам нужен port.Clock.
var testClock = testutil.FixedClock(time.Unix(0, 0))

// TestAppWaitTasksDegradedStagesStillRun — деградированный сценарий:
// scheduler-стадия превышает свою долю бюджета (вечный reconcile без
// ответа от Stop), а tasks-стадия всё равно выполняется и её ошибка
// попадает в агрегат. До сессии 35 abort-на-первой-ошибке пропускал
// WaitAll и DrainBackgroundDeletes ровно там, где они нужнее всего.
func TestAppWaitTasksDegradedStagesStillRun(t *testing.T) {
	// Scheduler без Start и без runners: Stop вернётся мгновенно —
	// «съесть» бюджет должен tasks. Задача висит 10s, доля tasks —
	// меньше: WaitAll вернёт DeadlineExceeded, дренаж обязан
	// выполниться после (пустой — мгновенно).
	sched := mirrorengine.NewScheduler(nil, testutil.NewFakeRemoteStore(), nil, testClock, 0)
	sched.Start(context.Background())

	tasks := web.NewTaskRegistry(1, testClock, nil)
	hangTaskDone := make(chan struct{})
	started := make(chan struct{})
	if _, err := tasks.Start("sync", "remote-a", func(ctx context.Context, _ web.Progress) error {
		close(started)
		defer close(hangTaskDone)
		<-ctx.Done() // слушает отмену, но выходим с задержкой
		time.Sleep(3 * time.Second)
		return ctx.Err()
	}); err != nil {
		t.Fatal(err)
	}
	<-started

	cache := cacheengine.New(testutil.NewFakeStorage(testClock), testutil.NewFakeObjectIndex(), nil, testClock, cacheengine.Config{}, nil)

	app := &App{Scheduler: sched, Tasks: tasks, Cache: cache}

	// Бюджет каскада 1s: доли (10/15/5s) не влезают — stages получат
	// ctx с уже горящим deadline? Нет: WithTimeout от ctx с 1s даст
	// каждой стадии максимум 1s. WaitAll не дождётся задачи (3s сна)
	// и вернёт ошибку — дренаж всё равно выполняется.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := app.WaitTasks(ctx)
	if err == nil {
		t.Fatal("ожидалась агрегированная ошибка (tasks-стадия не дождалась)")
	}
	if !strings.Contains(err.Error(), "tasks wait") {
		t.Errorf("в агрегате нет tasks wait: %v", err)
	}
	// scheduler-стадия обязана была пройти без ошибки (Stop сработал)
	if strings.Contains(err.Error(), "scheduler stop") {
		t.Errorf("scheduler-стадия упала в деградации без причины: %v", err)
	}
	// Дренаж не пропущен: ошибок "background deletes" нет, но стадия
	// выполнена — проверяем косвенно, что в агрегате только tasks.
	if strings.Contains(err.Error(), "background deletes") {
		t.Errorf("дренаж упал на пустом кеше: %v", err)
	}
}

// TestAppWaitTasksAllStagesSucceed — счастливый путь: все стадии
// завершаются, WaitTasks возвращает nil.
func TestAppWaitTasksAllStagesSucceed(t *testing.T) {
	sched := mirrorengine.NewScheduler(nil, testutil.NewFakeRemoteStore(), nil, testClock, 0)
	sched.Start(context.Background())

	tasks := web.NewTaskRegistry(1, testClock, nil)
	done := make(chan struct{})
	if _, err := tasks.Start("sync", "remote-b", func(ctx context.Context, _ web.Progress) error {
		defer close(done)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	<-done

	cache := cacheengine.New(testutil.NewFakeStorage(testClock), testutil.NewFakeObjectIndex(), nil, testClock, cacheengine.Config{}, nil)

	app := &App{Scheduler: sched, Tasks: tasks, Cache: cache}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.WaitTasks(ctx); err != nil {
		t.Fatalf("счастливый путь вернул ошибку: %v", err)
	}
	if tasks.HasActive() {
		t.Fatal("задача не завершилась после WaitTasks")
	}
}

// TestAppWaitTasksEmpty — пустое приложение (деградированный режим
// без модулей): WaitTasks — no-op без ошибки.
func TestAppWaitTasksEmpty(t *testing.T) {
	app := &App{}
	if err := app.WaitTasks(context.Background()); err != nil {
		t.Fatalf("пустое приложение вернуло ошибку: %v", err)
	}
}

// closeCountingAudit — фейк-каталог со счётчиком Close: стадия каскада
// обязана закрыть пул БД после остановки задач (сессия 79).
type closeCountingAudit struct{ closed bool }

func (a *closeCountingAudit) Record(context.Context, domain.AuditEntry) error { return nil }
func (a *closeCountingAudit) AuditEntries(context.Context, int64, int) ([]domain.AuditEntry, error) {
	return nil, nil
}
func (a *closeCountingAudit) Close() error { a.closed = true; return nil }

// TestAppWaitTasksClosesCatalog — финальная стадия WaitTasks закрывает
// каталог (type-assertion на io.Closer, как в addremote.go): серверный
// путь иначе никогда не звал db.Close().
func TestAppWaitTasksClosesCatalog(t *testing.T) {
	audit := &closeCountingAudit{}
	app := &App{Catalog: registry.CatalogSet{Audit: audit}}
	if err := app.WaitTasks(context.Background()); err != nil {
		t.Fatalf("WaitTasks с фейк-каталогом: %v", err)
	}
	if !audit.closed {
		t.Fatal("Close каталога не вызван хвостом WaitTasks")
	}
}

// TestPromRegistryRuntimeCollectors — реестр wire несёт go/process-
// коллекторы (аудит 2026-08-30): go_goroutines обязаны появляться в
// exposition. Процесс-метрики платформозависимы (без /proc — пусто),
// на них не ассертим (правило переносимости тестов).
func TestPromRegistryRuntimeCollectors(t *testing.T) {
	h := metrics.NewHandler(metrics.NewCache(), newPromRegistry())
	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "go_goroutines") {
		t.Errorf("в exposition нет go_goroutines — Go-коллектор не зарегистрирован")
	}
}
