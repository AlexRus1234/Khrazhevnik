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

// E2E выметающей чистки хранилища (storagegc, сессии 119–122) на
// реальной сборке компонентов: конфиг → sweeper → TaskRegistry →
// хранилище fs + каталог sqlite (включая ModTime реальных файлов).
// bootstrap/login → репо → upload (publish API) → DELETE (фоновая
// чистка префикса) → ручной POST /storage/gc (dry-run и реальный):
// хранилище чисто, живое на месте; счётчик удалённых ключей > 0.
// Сессия 123.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/ecosystem/apt"
	_ "khrazhevnik/internal/mod/storage/fs"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	publishengine "khrazhevnik/internal/core/engine/publish"
	"khrazhevnik/internal/core/engine/storagegc"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// storageGCEnv — live-сервер с реальным sqlite-каталогом, fs-хранилищем,
// publish-движком и sweep'ером, как делает wireApp. storeDir и catalog
// выставлены наружу ради белых вставок (прямая запись файлов, строка
// object_index, os.Chtimes) — прецедент byte-exact-тестов.
type storageGCEnv struct {
	srv      *web.Server
	admin    string
	storeDir string
	catalog  *registry.CatalogSet
}

// newStorageGCEnv собирает окружение с малым gc_grace (1s): grace
// проходит без sleep-хрупкости, а периодический цикл выключен
// (gc_interval=0) — тест дёргает только ручной проход.
func newStorageGCEnv(t *testing.T) *storageGCEnv {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	publicAddr := freePort(t)
	adminAddr := freePort(t)
	tomlCfg := "[server]\n" +
		"public_listen = \"" + publicAddr + "\"\n" +
		"admin_listen = \"" + adminAddr + "\"\n\n" +
		"[storage]\n" +
		"gc_interval = \"0s\"\n" +
		"gc_grace = \"1s\"\n\n" +
		"[storage.fs]\n" +
		"path = \"" + filepath.ToSlash(storeDir) + "\"\n\n" +
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
	storageFactory, err := registry.Storage(cfg.Storage.Driver)
	if err != nil {
		t.Fatal(err)
	}
	dbFactory, err := registry.DB(cfg.Database.Driver)
	if err != nil {
		t.Fatal(err)
	}
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
	// Часы — реальное «сейчас», не фиксированная дата: grace сравнивает
	// ModTime файлов на диске с now (фиксированное прошлое сделало бы
	// свежие файлы «будущим» и обнулило бы проверку возраста).
	clock := testutil.NewManualClock(time.Now())
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Revocations: catalog.Revocations,
		Clock: clock, Rand: testutil.FixedRand("77777777-7777-4777-8777-777777777777"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, http.DefaultClient, clock, cacheengine.Config{}, metrics.NewCache())
	ecosystems := map[string]port.Ecosystem{}
	for _, name := range registry.Ecosystems() {
		factory, err := registry.Ecosystem(name)
		if err != nil {
			continue
		}
		adapter, err := factory(config.Ecosystem{}, registry.EcosystemDeps{Remotes: catalog.Remotes, Clock: clock})
		if err != nil {
			continue
		}
		ecosystems[name] = adapter
	}
	tasks := web.NewTaskRegistry(4, clock, nil)

	sweeper := storagegc.New(storage, catalog.ObjIndex, catalog.Repos, clock, cfg.Storage.GCGrace.Duration)
	gcMetrics := metrics.NewStorageGC()
	sweeper.OnSweep = func(res storagegc.Result, err error) {
		gcMetrics.ObserveRun(res.Deleted, res.BytesFreed, res.FailedDeletes, res.Duration.Seconds())
	}
	reg := prometheus.NewRegistry()
	gcMetrics.Register(reg)
	metricsHandler := metrics.NewHandler(cacheEngine.Metrics(), reg).MetricsHandler()

	publishEngine := publishengine.New(publishengine.Config{MaxObjectSize: cfg.Publish.MaxObjectSize.Bytes}, storage, catalog.Repos, clock, wireRepoAdaptersForTest(nil, clock))
	publishAPI := publishSyncerTest{engine: publishEngine, repos: catalog.Repos, tasks: tasks}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr: publicAddr,
		PublicHandler: web.BuildPublicRouter(web.Deps{
			Log: log, Version: "test", Cache: cacheEngine, Storage: storage, Repos: catalog.Repos,
		}),
		AdminAddr: adminAddr,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService, Cache: cacheEngine,
			Ecosystems: ecosystems,
			Repos:      catalog.Repos, Storage: storage, Audit: catalog.Audit,
			Tasks: tasks, Publish: publishAPI, StorageGC: sweeper, Clock: clock,
			MetricsHandler: metricsHandler,
		}),
		Log:       log,
		WaitTasks: tasks.WaitAll,
	}
	return &storageGCEnv{srv: srv, admin: adminAddr, storeDir: storeDir, catalog: &catalog}
}

// TestStorageGCEndToEnd — полный цикл чистки через admin-API: живой
// репо удаляется и выметается фоновой задачей, ручной проход добивает
// мусор и осиротевшие versioned-ключи, dry-run ничего не трогает.
func TestStorageGCEndToEnd(t *testing.T) {
	env := newStorageGCEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- env.srv.Run(ctx) }()
	waitHealthy(t, "http://"+env.admin+"/healthz")

	post(t, "http://"+env.admin+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, env.admin, "admin", "password")

	// --- repo-путь: живой репо → upload → DELETE → фоновая чистка.
	repoBody := `{"name":"alice","owner_id":1,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0}}`
	resp := post(t, "http://"+env.admin+"/api/v1/repos", repoBody, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	repoID := int64(created["id"].(float64))

	deb := buildDebIntegration(t, "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: test\n")
	putURL := fmt.Sprintf("http://%s/api/v1/repos/%d/objects/pool/main/f/foo.deb", env.admin, repoID)
	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(deb))
	req.ContentLength = int64(len(deb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT .deb = %d, хочу 201", putResp.StatusCode)
	}
	storedKey := fmt.Sprintf("repo/%d/apt/pool/main/f/foo.deb", repoID)
	if !storageFileExists(t, env.storeDir, storedKey) {
		t.Fatalf("upload не создал %s", storedKey)
	}

	deleteReq(t, fmt.Sprintf("http://%s/api/v1/repos/%d", env.admin, repoID), token, 204)
	waitTaskByLabel(t, env.admin, token, "gc", fmt.Sprintf("repo-%d", repoID))
	if n := countStorageFiles(t, env.storeDir, fmt.Sprintf("repo/%d/", repoID)); n != 0 {
		t.Fatalf("после DELETE в repo/%d/ осталось %d файлов (сессия 122)", repoID, n)
	}

	// Sweep-путь: мусор удалённого репо → ручной проход → выметен.
	garbageKey := fmt.Sprintf("repo/%d/residue.bin", repoID)
	writeStorageFile(t, env.storeDir, garbageKey, []byte("junk"))
	runStorageGC(t, env, token, "")
	if storageFileExists(t, env.storeDir, garbageKey) {
		t.Fatalf("ручной sweep не вымел %s", garbageKey)
	}

	// --- cache-путь: живые и осиротевшие versioned-ключи.
	const (
		logicalKey = "cache/apt/foo/Packages"
		keyLive    = logicalKey + "-v000000000001"
		keyOrphan  = logicalKey + "-v000000000002"
		// «Чужое имя» без строки в object_index: суффикс версии есть,
		// логического ключа нет — правило (c) обязано пощадить.
		keyForeign = "cache/apt/other/Packages-v000000000003"
	)
	if err := env.catalog.ObjIndex.PutObjectMeta(ctx, domain.ObjectMeta{
		Key: logicalKey, StorageKey: keyLive,
	}); err != nil {
		t.Fatal(err)
	}
	writeStorageFile(t, env.storeDir, keyLive, []byte("live"))
	writeStorageFile(t, env.storeDir, keyOrphan, []byte("orphan"))
	writeStorageFile(t, env.storeDir, keyForeign, []byte("foreign"))
	old := time.Now().Add(-time.Hour)
	ageStorageFile(t, env.storeDir, keyOrphan, old)
	ageStorageFile(t, env.storeDir, keyForeign, old)

	// dry_run на тех же сидах: снимок кандидатов, удалений нет.
	runStorageGC(t, env, token, "?dry_run=true")
	for _, key := range []string{keyLive, keyOrphan, keyForeign} {
		if !storageFileExists(t, env.storeDir, key) {
			t.Fatalf("dry_run удалил %s", key)
		}
	}

	// Реальный проход: сирота выметен, живой и «чужой» ключи на месте.
	runStorageGC(t, env, token, "")
	if storageFileExists(t, env.storeDir, keyOrphan) {
		t.Fatalf("реальный проход не вымел сироту %s", keyOrphan)
	}
	if !storageFileExists(t, env.storeDir, keyLive) {
		t.Fatalf("выметен живой ключ %s (storage_key из object_index)", keyLive)
	}
	if !storageFileExists(t, env.storeDir, keyForeign) {
		t.Fatalf("выметен ключ без строки %s (правило (c))", keyForeign)
	}

	// /metrics: счётчик удалённых чисткой ключей ненулевой.
	body := get(t, "http://"+env.admin+"/metrics", token, 200)
	if v := metricValue(t, string(body), "khrazhevnik_storage_gc_deleted_keys_total"); v <= 0 {
		t.Fatalf("khrazhevnik_storage_gc_deleted_keys_total = %v, хочу > 0", v)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}

// runStorageGC запускает ручной проход (query — "" или "?dry_run=true")
// и ждёт завершения задачи по её id из 202-ответа (label «storage»
// повторяется между вызовами — поллинг списка поймал бы прошлую задачу).
func runStorageGC(t *testing.T, env *storageGCEnv, token, query string) {
	t.Helper()
	resp := post(t, "http://"+env.admin+"/api/v1/storage/gc"+query, "", token, 202)
	var out map[string]string
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if out["task_id"] == "" {
		t.Fatalf("202 без task_id: %s", resp)
	}
	waitTaskByID(t, env.admin, token, out["task_id"])
}

// waitTaskByID ждёт задачи по id до succeeded (failed — тест).
func waitTaskByID(t *testing.T, adminAddr, token, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		body := get(t, "http://"+adminAddr+"/api/v1/tasks/"+id, token, 200)
		var task map[string]any
		if err := json.Unmarshal(body, &task); err != nil {
			t.Fatal(err)
		}
		switch task["state"] {
		case "succeeded":
			return
		case "failed":
			errText, _ := task["error"].(string)
			t.Fatalf("задача %s упала: %s", id, errText)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("задача %s не завершилась за 5с", id)
}

// waitTaskByLabel ждёт по списку /tasks задачу kind|label до succeeded.
func waitTaskByLabel(t *testing.T, adminAddr, token, kind, label string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		body := get(t, "http://"+adminAddr+"/api/v1/tasks", token, 200)
		var snaps []map[string]any
		if err := json.Unmarshal(body, &snaps); err != nil {
			t.Fatal(err)
		}
		for _, s := range snaps {
			if s["kind"] != kind || s["label"] != label {
				continue
			}
			switch s["state"] {
			case "succeeded":
				return
			case "failed":
				errText, _ := s["error"].(string)
				t.Fatalf("задача %s|%s упала: %s", kind, label, errText)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("задача %s|%s не завершилась за 5с", kind, label)
}

// metricValue достаёт значение counter'а из тела /metrics.
func metricValue(t *testing.T, body, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("метрика %s: %v (%q)", name, err, line)
		}
		return v
	}
	t.Fatalf("метрика %s не найдена в /metrics", name)
	return 0
}

// storagePath переводит ключ объекта в путь от корня хранилища.
func storagePath(root, key string) string {
	return filepath.Join(root, filepath.FromSlash(key))
}

// writeStorageFile кладёт файл по ключу (белая вставка в fs-хранилище).
func writeStorageFile(t *testing.T, root, key string, data []byte) {
	t.Helper()
	p := storagePath(root, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ageStorageFile выставляет ModTime файла в прошлое (обычная операция,
// не экзотика) — grace-правило sweeper'а проверяется по возрасту.
func ageStorageFile(t *testing.T, root, key string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(storagePath(root, key), when, when); err != nil {
		t.Fatal(err)
	}
}

// storageFileExists сообщает, есть ли файл по ключу.
func storageFileExists(t *testing.T, root, key string) bool {
	t.Helper()
	_, err := os.Stat(storagePath(root, key))
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	t.Fatalf("stat %q: %v", key, err)
	return false
}

// countStorageFiles считает объекты под префиксом (отсутствие
// каталога — ноль, не ошибка).
func countStorageFiles(t *testing.T, root, prefix string) int {
	t.Helper()
	base := filepath.Join(root, filepath.FromSlash(prefix))
	n := 0
	err := filepath.WalkDir(base, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("обход %s: %v", prefix, err)
	}
	return n
}
