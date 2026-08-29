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

// E2E админ-API: реальный sqlite-каталог + фейк remotes/audit →
// /api/v1/remotes CRUD, /audit пагинация, /tasks/{id} после sync.
// Сессия 09.

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/storage/fs"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// adminIntegrationEnv собирает реальный sqlite-каталог и live-роутер
// админки, как делает wireApp, но в тесте — для проверки API-контракта.
func adminIntegrationEnv(t *testing.T) (*web.Server, *registry.CatalogSet, *web.TaskRegistry) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	tomlCfg := "[server]\n" +
		"public_listen = \"" + freePort(t) + "\"\n" +
		"admin_listen = \"" + freePort(t) + "\"\n\n" +
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
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Revocations: catalog.Revocations,
		Clock: clock, Rand: testutil.FixedRand("55555555-5555-4555-8555-555555555555"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Первый admin через /setup (без setup_token в конфиге — просто).
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, http.DefaultClient, clock, cacheengine.Config{}, metrics.NewCache())
	tasks := web.NewTaskRegistry(2, clock)
	metricsHandler := metrics.NewHandler(cacheEngine.Metrics(), prometheus.NewRegistry()).MetricsHandler()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: "test"}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService, Cache: cacheEngine,
			Remotes: catalog.Remotes, Audit: catalog.Audit, Tasks: tasks,
			MetricsHandler: metricsHandler, Clock: clock,
		}),
		Log:       log,
		WaitTasks: tasks.WaitAll,
	}
	return srv, &catalog, tasks
}

// TestAdminAPIRemotesCRUDLive — реальный sqlite, полный цикл
// /api/v1/remotes через HTTP: setup → login → create → list → patch → delete.
func TestAdminAPIRemotesCRUDLive(t *testing.T) {
	srv, _, _ := adminIntegrationEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	_, adminAddr := srv.Addrs()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	// setup admin
	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	// login
	token := login(t, adminAddr, "admin", "password")

	// create remote
	body := `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}`
	resp := post(t, "http://"+adminAddr+"/api/v1/remotes", body, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	if created["name"] != "debian" {
		t.Errorf("created remote = %v", created)
	}

	// list
	list := get(t, "http://"+adminAddr+"/api/v1/remotes", token, 200)
	var items []map[string]any
	if err := json.Unmarshal(list, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("list = %d items, хочу 1", len(items))
	}

	// patch
	patch := `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian/","mode":"mirror","enabled":false}`
	got := patchReq(t, "http://"+adminAddr+"/api/v1/remotes/1", patch, token, 200)
	var updated map[string]any
	if err := json.Unmarshal(got, &updated); err != nil {
		t.Fatal(err)
	}
	if updated["mode"] != "mirror" {
		t.Errorf("patched mode = %v", updated)
	}

	// delete
	deleteReq(t, "http://"+adminAddr+"/api/v1/remotes/1", token, 204)
	// list empty
	list = get(t, "http://"+adminAddr+"/api/v1/remotes", token, 200)
	if err := json.Unmarshal(list, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("после delete list = %d items, хочу 0", len(items))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}

// TestAdminAuditPaginationLive — реальный sqlite, пагинация аудита.
func TestAdminAuditPaginationLive(t *testing.T) {
	srv, catalog, _ := adminIntegrationEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	_, adminAddr := srv.Addrs()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")

	// Базовые записи аудита: setup (1) + login OK (1) = 2.
	baseEntries, err := catalog.Audit.AuditEntries(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	base := len(baseEntries)

	// Пишем 25 записей через прямой порт (имитация мутаций).
	for i := 0; i < 25; i++ {
		if err := catalog.Audit.Record(ctx, domain.AuditEntry{
			At: time.Now().UTC(), Actor: "system",
			Action: "test.op", Object: "x", Result: domain.AuditOK,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Первая страница 10.
	page1 := get(t, "http://"+adminAddr+"/api/v1/audit?limit=10", token, 200)
	var p1 []map[string]any
	if err := json.Unmarshal(page1, &p1); err != nil {
		t.Fatal(err)
	}
	if len(p1) != 10 {
		t.Fatalf("страница 1 = %d, хочу 10", len(p1))
	}
	lastID := int64(p1[len(p1)-1]["id"].(float64))
	// Вторая страница 10.
	page2 := get(t, fmt.Sprintf("http://%s/api/v1/audit?after_id=%d&limit=10", adminAddr, lastID), token, 200)
	var p2 []map[string]any
	if err := json.Unmarshal(page2, &p2); err != nil {
		t.Fatal(err)
	}
	if len(p2) != 10 {
		t.Fatalf("страница 2 = %d, хочу 10", len(p2))
	}
	lastID = int64(p2[len(p2)-1]["id"].(float64))
	// Третья — остаток (base + 25 - 20).
	rest := base + 25 - 20
	page3 := get(t, fmt.Sprintf("http://%s/api/v1/audit?after_id=%d&limit=10", adminAddr, lastID), token, 200)
	var p3 []map[string]any
	if err := json.Unmarshal(page3, &p3); err != nil {
		t.Fatal(err)
	}
	if len(p3) != rest {
		t.Fatalf("страница 3 = %d, хочу %d", len(p3), rest)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}

// TestAdminMetricsLive — /metrics отдаёт 200 за admin session.
func TestAdminMetricsLive(t *testing.T) {
	srv, _, _ := adminIntegrationEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	_, adminAddr := srv.Addrs()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")

	// /metrics без auth — 401.
	resp, err := http.Get("http://" + adminAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics без auth = %d, хочу 401", resp.StatusCode)
	}
	// С admin session — 200 и содержит имя метрики.
	req, _ := http.NewRequest(http.MethodGet, "http://"+adminAddr+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics = %d, хочу 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "khrazhevnik_cache_hits_total") {
		t.Errorf("в /metrics нет имени метрики:\n%s", body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}

// TestAdminSetupAtomicLive — 20 параллельных POST /setup на пустой
// базе: ровно один 201, остальные 403, один пользователь (аудит
// 2026-08-27, интеграционный аналог firstUserAtomicSuite). Источники —
// разные loopback-адреса 127.x: /setup под login-rate-limit, одна
// корзина превратила бы гонку в тест лимитера.
func TestAdminSetupAtomicLive(t *testing.T) {
	srv, catalog, _ := adminIntegrationEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	_, adminAddr := srv.Addrs()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	const writers = 20
	codes := make(chan int, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client := &http.Client{Transport: &http.Transport{
				DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0." + itoaInt(1+i%250))}}).DialContext,
			}}
			req, _ := http.NewRequest(http.MethodPost,
				"http://"+adminAddr+"/api/v1/setup",
				strings.NewReader(`{"username":"racer","password":"password"}`))
			resp, err := client.Do(req)
			if err != nil {
				codes <- -1
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			codes <- resp.StatusCode
		}(i)
	}
	wg.Wait()
	close(codes)
	created := 0
	for code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusForbidden, -1:
			// -1 — локальный dial-сбой экзотического loopback (не каскадит)
		default:
			t.Errorf("неожиданный статус /setup в гонке: %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("создано админов %d, хочу ровно 1", created)
	}
	users, err := catalog.Users.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("в таблице %d пользователей, хочу 1", len(users))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}

// itoaInt — локальная обёртка strconv.Itoa.
func itoaInt(n int) string { return strconv.Itoa(n) }

// post — HTTP POST с bearer, проверяет статус.
func post(t *testing.T, url, body, bearer string, want int) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("POST %s = %d, хочу %d (тело %s)", url, resp.StatusCode, want, b)
	}
	return b
}

func get(t *testing.T, url, bearer string, want int) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("GET %s = %d, хочу %d (тело %s)", url, resp.StatusCode, want, b)
	}
	return b
}

func patchReq(t *testing.T, url, body, bearer string, want int) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("PATCH %s = %d, хочу %d (тело %s)", url, resp.StatusCode, want, b)
	}
	return b
}

func deleteReq(t *testing.T, url, bearer string, want int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("DELETE %s = %d, хочу %d", url, resp.StatusCode, want)
	}
}

func login(t *testing.T, addr, user, pass string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/api/v1/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	var m map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m["token"]
}
