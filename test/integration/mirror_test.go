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

//go:build integration

// E2E зеркало: планировщик с reconcile-циклом (сессия 23) подхватывает
// remote, созданный через admin-API после старта процесса, без
// рестарта: POST /api/v1/remotes → notify → reconcile → runner → sync.

package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/storage/fs"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	mirrorengine "khrazhevnik/internal/core/engine/mirror"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// mirrorSyncerTest — копия cmd.mirrorSyncer: обёртка mirror.Engine под
// web.MirrorSync (запуск sync как фоновой задачи TaskRegistry).
type mirrorSyncerTest struct {
	engine  *mirrorengine.Engine
	remotes port.RemoteStore
	tasks   *web.TaskRegistry
}

func (m mirrorSyncerTest) Sync(ctx context.Context, remoteID int64) (string, error) {
	remote, err := m.remotes.Remote(ctx, remoteID)
	if err != nil {
		return "", err
	}
	return m.tasks.Start("sync", remote.Name, func(ctx context.Context, p web.Progress) error {
		fresh, err := m.remotes.Remote(ctx, remoteID)
		if err != nil {
			return fmt.Errorf("sync: remote: %w", err)
		}
		return m.engine.Sync(ctx, fresh, mirrorProgressTest{p: p})
	})
}

type mirrorProgressTest struct{ p web.Progress }

func (mp mirrorProgressTest) Update(phase, current string, processed, total int64) {
	mp.p.Update(phase, current, processed, total)
}
func (mp mirrorProgressTest) Log(line string) { mp.p.Log(line) }

// TestMirrorSchedulerPicksUpRemoteViaAPI — remote, добавленный через
// admin-API после старта процесса (mode=mirror, интервал задан),
// начинает синхронизироваться без рестарта: notify → reconcile →
// runner → sync → sync_jobs succeeded.
func TestMirrorSchedulerPicksUpRemoteViaAPI(t *testing.T) {
	// фейк-upstream: отдаёт байты на любой путь, считает запросы
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("package-bytes"))
	}))
	defer up.Close()

	dir := t.TempDir()
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	publicAddr := freePort(t)
	adminAddr := freePort(t)
	tomlCfg := "[server]\n" +
		"public_listen = \"" + publicAddr + "\"\n" +
		"admin_listen = \"" + adminAddr + "\"\n\n" +
		"[storage.fs]\n" +
		"path = \"" + filepath.ToSlash(filepath.Join(dir, "store")) + "\"\n\n" +
		"[database]\n" +
		"dsn = \"" + filepath.ToSlash(filepath.Join(dir, "khrazhevnik.db")) + "\"\n\n" +
		"[auth]\n" +
		"jwt_secret = \"integration-secret-integration-secret-0123\"\n"
	if err := os.WriteFile(confPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(confPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	storageFactory, _ := registry.Storage(cfg.Storage.Driver)
	dbFactory, _ := registry.DB(cfg.Database.Driver)
	storage, err := storageFactory(cfg.Storage)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := dbFactory(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := catalog.Audit.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	clock := testutil.NewManualClock(time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit,
		Clock: clock, Rand: testutil.FixedRand("77777777-7777-4777-8777-777777777777"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, up.Client(), clock,
		cacheengine.Config{}, metrics.NewCache())
	tasks := web.NewTaskRegistry(2, clock)
	// экосистема «t»: enumerate отдаёт один пакет; upstream выше
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, EnumeratePaths: []string{"/a.deb"}}
	ecos := map[string]port.Ecosystem{"t": eco}
	mirrorEngine := mirrorengine.New(mirrorengine.Config{Workers: 1},
		cacheEngine, storage, catalog.ObjIndex, catalog.Remotes, catalog.Jobs, clock, ecos)
	mirrorAPI := mirrorSyncerTest{engine: mirrorEngine, remotes: catalog.Remotes, tasks: tasks}
	scheduler := mirrorengine.NewScheduler(mirrorEngine, catalog.Remotes, testutil.RealRand(), clock, 0)
	scheduler.Start(context.Background())
	t.Cleanup(func() { _ = scheduler.Stop(context.Background()) })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: "test", Cache: cacheEngine, Ecosystems: ecos, Storage: storage}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService,
			Remotes: catalog.Remotes, Audit: catalog.Audit,
			Tasks: tasks, Mirror: mirrorAPI, Clock: clock,
			OnRemotesChanged: scheduler.Notify,
		}),
		Log:       log,
		WaitTasks: scheduler.Stop,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")

	// admin-API: создаём mirror-remote ПОСЛЕ старта планировщика.
	// sync_interval — time.Duration в наносекундах; адаптеры БД хранят
	// его целыми секундами (sync_interval_sec), берём 1с — минимальный
	// авто-интервал, который доживает до БД без усечения в «вручную».
	body := `{"name":"pkg","ecosystem":"t","base_url":"` + up.URL + `","mode":"mirror","enabled":true,"sync_interval":1000000000}`
	post(t, "http://"+adminAddr+"/api/v1/remotes", body, token, 201)

	// без рестарта: remote подхватывается и sync скачивает пакет
	// (первый тик — через sync_interval, запас — на медленный CI)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("remote, добавленный через admin-API, не синхронизировался")
	}

	// hits инкрементятся посреди скачивания — финальный статус пишется
	// после завершения sync; поллим как publish-тесты
	deadline = time.Now().Add(5 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		jobs, jerr := catalog.Jobs.Jobs(context.Background())
		if jerr == nil && len(jobs) > 0 {
			state = string(jobs[0].State)
			if state == "succeeded" || state == "failed" {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "succeeded" {
		t.Fatalf("sync_jobs.state = %q, хочу succeeded", state)
	}
	// первый тик не должен задвоить скачивание (diff пуст на второй)
	time.Sleep(50 * time.Millisecond)
	if got := hits.Load(); got > 2 {
		t.Errorf("upstream получил %d запросов за два тика, хочу ≤2", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}
