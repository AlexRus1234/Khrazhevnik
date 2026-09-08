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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// adminEnv — собранные депсы админ-роутера с фейковым каталогом и
// часовами; каждый тест получает свежие фейки.
type adminEnv struct {
	handler  http.Handler
	auth     *auth.Service
	remotes  *testutil.FakeRemoteStore
	audit    *testutil.FakeAuditLog
	tasks    *TaskRegistry
	clock    *testutil.ManualClock
	jwtAdmin string
	jwtUser  string
	apiAdmin string
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tokens := &handlerTokens{}
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	a, err := auth.New(auth.Config{
		Users: users, Tokens: tokens, Audit: nil, Revocations: testutil.NewFakeRevocations(),
		Clock: clock, Rand: testutil.FixedRand("44444444-4444-4444-8444-444444444444"),
		JWTSecret: "secret", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Создаём admin и user через сервис, чтобы bcrypt-хеши были валидны.
	admin, err := a.CreateUser(t.Context(), "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := a.CreateUser(t.Context(), "user", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	jwtAdmin, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	jwtUser, err := a.IssueSession(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	_, apiAdmin, err := a.IssueAPIToken(t.Context(), admin, "admin-token", []domain.Scope{domain.ScopeAdmin}, 0)
	if err != nil {
		t.Fatal(err)
	}
	remotes := testutil.NewFakeRemoteStore()
	auditLog := testutil.NewFakeAuditLog()
	tasks := NewTaskRegistry(2, clock, nil)
	// mirrorStub — web.MirrorSync для тестов: запускает задачу sync,
	// которая сразу завершается (не настоящий движок зеркала — он
	// тестируется в internal/core/engine/mirror). Хватает проверить
	// API-контракт: 202 + task_id, дубль → 409, задача видна в /tasks.
	mirror := mirrorStub{remotes: remotes, tasks: tasks}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Remotes: remotes, Audit: auditLog, Tasks: tasks, Mirror: mirror, Clock: clock,
	})
	return &adminEnv{
		handler: h, auth: a, remotes: remotes, audit: auditLog,
		tasks: tasks, clock: clock,
		jwtAdmin: jwtAdmin, jwtUser: jwtUser, apiAdmin: apiAdmin,
	}
}

// mirrorStub — web.MirrorSync для админ-тестов: запускает sync
// как задачу TaskRegistry с тривиальным воркером (ctx.Done → отмена).
// Не настоящий движок зеркала — только API-контракт.
type mirrorStub struct {
	remotes port.RemoteStore
	tasks   *TaskRegistry
}

func (m mirrorStub) Sync(ctx context.Context, remoteID int64) (string, error) {
	remote, err := m.remotes.Remote(ctx, remoteID)
	if err != nil {
		return "", err
	}
	return m.tasks.Start("sync", remote.Name, func(ctx context.Context, p Progress) error {
		p.Log("sync (тест-заглушка)")
		p.Update("pending", "stub", 0, 1)
		<-ctx.Done()
		return ctx.Err()
	})
}

// callAdmin — HTTP-вызов с опциональным bearer.
func callAdmin(env *adminEnv, method, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "10.0.0.9:1"
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, r)
	return rec
}

// TestCreateUserPasswordMinimumLength — POST /users с пустым паролем
// даёт 400 validation_error от движка (отдельной валидации в хендлере
// нет — движок единственная точка), а не 500/201.
func TestCreateUserPasswordMinimumLength(t *testing.T) {
	env := newAdminEnv(t)
	rec := callAdmin(env, http.MethodPost, "/api/v1/users", `{"username":"bob","password":"","role":"user"}`, env.jwtAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /users (пустой пароль) = %d, хочу 400 (тело %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "validation_error") {
		t.Fatalf("тело %s, хочу validation_error", rec.Body.String())
	}
}

func TestAdminRemotesCRUD(t *testing.T) {
	env := newAdminEnv(t)

	// Create.
	body := `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}`
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, env.jwtAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create remote = %d, тело %s", rec.Code, rec.Body.String())
	}
	var created remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 || created.Name != "debian" || created.BaseURL != "https://deb.debian.org/debian" {
		t.Errorf("создан неверный remote: %+v", created)
	}

	// List.
	rec = callAdmin(env, http.MethodGet, "/api/v1/remotes", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("list remotes = %d", rec.Code)
	}
	var list []remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Errorf("list = %+v", list)
	}

	// Update (PATCH).
	body = `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian/","mode":"mirror","enabled":false}`
	rec = callAdmin(env, http.MethodPatch, "/api/v1/remotes/1", body, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("update remote = %d, тело %s", rec.Code, rec.Body.String())
	}
	var updated remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Mode != domain.ModeMirror || updated.Enabled {
		t.Errorf("update не применился: %+v", updated)
	}
	// base_url без хвостового слэша (нормализация).
	if updated.BaseURL != "https://deb.debian.org/debian" {
		t.Errorf("base_url не нормализован: %q", updated.BaseURL)
	}

	// Delete.
	rec = callAdmin(env, http.MethodDelete, "/api/v1/remotes/1", "", env.jwtAdmin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete remote = %d", rec.Code)
	}
	// Повторный delete — 404.
	rec = callAdmin(env, http.MethodDelete, "/api/v1/remotes/1", "", env.jwtAdmin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("повторный delete = %d, хочу 404", rec.Code)
	}
}

func TestAdminRemotesValidation(t *testing.T) {
	env := newAdminEnv(t)
	for _, tc := range []struct {
		name, body string
		wantCode   string
	}{
		{"empty name", `{"name":"","ecosystem":"apt","base_url":"https://x","mode":"proxy"}`, "validation_error"},
		{"bad url", `{"name":"x","ecosystem":"apt","base_url":"not-a-url","mode":"proxy"}`, "validation_error"},
		{"bad mode", `{"name":"x","ecosystem":"apt","base_url":"https://x","mode":"weird"}`, "validation_error"},
		{"empty eco", `{"name":"x","ecosystem":"","base_url":"https://x","mode":"proxy"}`, "validation_error"},
		{"bad json", `{"name":"x"`, "invalid_json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", tc.body, env.jwtAdmin)
			var e apiError
			if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
				t.Fatalf("тело = %q, хочу apiError", rec.Body.String())
			}
			if e.Code != tc.wantCode {
				t.Errorf("код = %q, хочу %q (status %d)", e.Code, tc.wantCode, rec.Code)
			}
		})
	}
}

func TestAdminRemotesAuthMatrix(t *testing.T) {
	env := newAdminEnv(t)
	for _, tc := range []struct {
		name, bearer, remoteName string
		want                     int
	}{
		{"no auth", "", "r0", http.StatusUnauthorized},
		{"user role", env.jwtUser, "r1", http.StatusForbidden},
		{"admin session", env.jwtAdmin, "r2", http.StatusCreated},
		{"admin api token", env.apiAdmin, "r3", http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"name":"` + tc.remoteName + `","ecosystem":"apt","base_url":"https://x","mode":"proxy"}`
			rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, tc.bearer)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, хочу %d (тело %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestAdminSyncRemoteReturnsTaskID(t *testing.T) {
	env := newAdminEnv(t)
	// Сначала создаём remote.
	body := `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"mirror"}`
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, env.jwtAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	// /remotes/1/sync → 202 + task_id.
	rec = callAdmin(env, http.MethodPost, "/api/v1/remotes/1/sync", "", env.jwtAdmin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("sync = %d, тело %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TaskID == "" {
		t.Error("task_id пустой")
	}
	// Задача видна в /tasks.
	rec = callAdmin(env, http.MethodGet, "/api/v1/tasks/"+resp.TaskID, "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("get task = %d", rec.Code)
	}
	// Дублирующий sync того же remote — 409 ( задача sync|debian уже бегёт).
	rec = callAdmin(env, http.MethodPost, "/api/v1/remotes/1/sync", "", env.jwtAdmin)
	if rec.Code != http.StatusConflict {
		t.Errorf("повторный sync = %d, хочу 409", rec.Code)
	}
}

func TestAdminSyncRemoteNotFound(t *testing.T) {
	env := newAdminEnv(t)
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes/999/sync", "", env.jwtAdmin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sync несуществующего = %d, хочу 404", rec.Code)
	}
}

func TestAdminTasksList(t *testing.T) {
	env := newAdminEnv(t)
	// Без задач — пустой список (json.Encoder добавляет trailing newline).
	rec := callAdmin(env, http.MethodGet, "/api/v1/tasks", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	got := strings.TrimRight(rec.Body.String(), "\n")
	if got != "null" && got != "[]" {
		t.Errorf("пустой список tasks = %q, хочу null/[]", got)
	}
}

func TestAdminTaskNotFound(t *testing.T) {
	env := newAdminEnv(t)
	rec := callAdmin(env, http.MethodGet, "/api/v1/tasks/no-such", "", env.jwtAdmin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("несуществующий task = %d, хочу 404", rec.Code)
	}
	// Деградация (Tasks==nil): список — 200 «пусто», конкретный id —
	// 404: контракт api.md 200/404, id без реестра не существует
	// (аудит 2026-08-30, сессия 45).
	degraded := BuildAdminRouter(Deps{Auth: env.auth, Clock: env.clock})
	get := func(path string) int {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
		w := httptest.NewRecorder()
		degraded.ServeHTTP(w, r)
		return w.Code
	}
	if code := get("/api/v1/tasks"); code != http.StatusOK {
		t.Errorf("degraded список = %d, хочу 200 []", code)
	}
	if code := get("/api/v1/tasks/anything"); code != http.StatusNotFound {
		t.Errorf("degraded задача = %d, хочу 404", code)
	}
}

func TestAdminCacheStats(t *testing.T) {
	env := newAdminEnv(t)
	rec := callAdmin(env, http.MethodGet, "/api/v1/cache/stats", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var stats cacheStatsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Hits != 0 || stats.Misses != 0 || stats.HitRatio != 0 {
		t.Errorf("пустой кеш отдал статистику: %+v", stats)
	}
}

// TestAdminCacheStatsLive — живой разрез /api/v1/cache/stats (сессия
// 83, CI-факт №5 distro-test): трафик через движок отражается в
// агрегатах. newAdminEnv Cache не подаёт — до сессии 83 живую ветку
// агрегации гонял только пустой кеш, корневые нули не замечались.
func TestAdminCacheStatsLive(t *testing.T) {
	env := newAdminEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload")
	}))
	t.Cleanup(up.Close)
	engine := cacheengine.New(
		testutil.NewFakeStorage(env.clock), testutil.NewFakeObjectIndex(),
		up.Client(), env.clock, cacheengine.Config{}, nil,
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: time.Minute}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Clock: env.clock, Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"t": eco},
	})
	// Трафик через движок: MISS + HIT по 7 байт.
	for range 2 {
		obj, _, err := engine.FetchStatus(t.Context(), eco, "/t/pkg/a.deb")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(obj.Body)
		_ = obj.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var stats cacheStatsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Hits < 1 || stats.Misses < 1 {
		t.Errorf("hits/misses = %d/%d, хочу ≥1/≥1 (контракт broken distro-check)", stats.Hits, stats.Misses)
	}
	if stats.HitRatio <= 0 {
		t.Errorf("hit_ratio = %f, хочу >0", stats.HitRatio)
	}
	if stats.BytesFromUpstream < 7 {
		t.Errorf("bytes_from_upstream = %d, хочу ≥7", stats.BytesFromUpstream)
	}
}

// TestAdminCacheStatsPerEcosystem — per-eco разрез в /api/v1/cache/stats
// (сессия 92): каждая экосистема получает свой ряд с теми же полями,
// что и глобал; суммы рядов равны глобальным полям.
func TestAdminCacheStatsPerEcosystem(t *testing.T) {
	env := newAdminEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload")
	}))
	t.Cleanup(up.Close)
	engine := cacheengine.New(
		testutil.NewFakeStorage(env.clock), testutil.NewFakeObjectIndex(),
		up.Client(), env.clock, cacheengine.Config{}, nil,
	)
	eco1 := testutil.FakeEcosystem{NameOf: "t1", Base: up.URL, MutableTTL: time.Minute}
	eco2 := testutil.FakeEcosystem{NameOf: "t2", Base: up.URL, MutableTTL: time.Minute}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Clock: env.clock, Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"t1": eco1, "t2": eco2},
	})
	// t1: MISS + HIT (тот же путь дважды); t2: только MISS.
	for _, ecoPath := range []struct {
		eco  testutil.FakeEcosystem
		path string
	}{{eco1, "/t1/pkg/a.deb"}, {eco1, "/t1/pkg/a.deb"}, {eco2, "/t2/pkg/b.deb"}} {
		obj, _, err := engine.FetchStatus(t.Context(), ecoPath.eco, ecoPath.path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(obj.Body)
		_ = obj.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var stats cacheStatsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.PerEcosystem) != 2 {
		t.Fatalf("per_ecosystem = %d рядов, хочу 2: %+v", len(stats.PerEcosystem), stats.PerEcosystem)
	}
	if stats.PerEcosystem[0].Ecosystem != "t1" || stats.PerEcosystem[1].Ecosystem != "t2" {
		t.Errorf("порядок рядов = %s,%s, хочу лексический t1,t2", stats.PerEcosystem[0].Ecosystem, stats.PerEcosystem[1].Ecosystem)
	}
	t1, t2 := stats.PerEcosystem[0], stats.PerEcosystem[1]
	if t1.Hits != 1 || t1.Misses != 1 || t1.HitRatio != 0.5 {
		t.Errorf("t1 = %d/%d/%f, хочу 1/1/0.5", t1.Hits, t1.Misses, t1.HitRatio)
	}
	if t2.Hits != 0 || t2.Misses != 1 || t2.HitRatio != 0 {
		t.Errorf("t2 = %d/%d/%f, хочу 0/1/0", t2.Hits, t2.Misses, t2.HitRatio)
	}
	if stats.Hits != t1.Hits+t2.Hits || stats.Misses != t1.Misses+t2.Misses ||
		stats.BytesFromUpstream != t1.BytesFromUpstream+t2.BytesFromUpstream {
		t.Errorf("глобал %+v ≠ сумма рядов %+v", stats, stats.PerEcosystem)
	}
	// Счётчик пакетов (сессия 93): immutable-объект по каждой
	// экосистеме закеширован — поле и в ряду, и в глобальной сумме.
	if stats.Packages < 1 {
		t.Errorf("packages = %d, хочу ≥1", stats.Packages)
	}
	if t1.Packages < 1 || t2.Packages < 1 {
		t.Errorf("per-eco packages t1/t2 = %d/%d, хочу ≥1/≥1", t1.Packages, t2.Packages)
	}
	if stats.Packages != t1.Packages+t2.Packages {
		t.Errorf("глобальный packages = %d ≠ сумма рядов %d", stats.Packages, t1.Packages+t2.Packages)
	}
}

// resetCountingStats — фейк StatsStore со счётчиком ResetStats и
// инжектируемой ошибкой: контрактам сброса (сессия 97) нужно «вызван
// ли БД-сброс» и «503 при сбое», которых базовый FakeStatsStore не
// даёт.
type resetCountingStats struct {
	*testutil.FakeStatsStore
	calls int
	err   error
}

func (s *resetCountingStats) ResetStats(_ context.Context) error {
	s.calls++
	return s.err
}

// TestAdminCacheStatsReset — контракт POST /api/v1/cache/stats/reset
// (сессия 97): обнуление атомиков и БД-снапшота одним POST, 503 при
// сбое БД с живыми атомиками, аудит под cache.stats.reset,
// идемпотентность. Образец живого харнесса — TestAdminCacheStatsLive.
func TestAdminCacheStatsReset(t *testing.T) {
	env := newAdminEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload")
	}))
	t.Cleanup(up.Close)
	engine := cacheengine.New(
		testutil.NewFakeStorage(env.clock), testutil.NewFakeObjectIndex(),
		up.Client(), env.clock, cacheengine.Config{}, nil,
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: time.Minute}
	stats := &resetCountingStats{FakeStatsStore: testutil.NewFakeStatsStore()}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Clock: env.clock, Cache: engine, Stats: stats, Audit: env.audit,
		Ecosystems: map[string]port.Ecosystem{"t": eco},
	})
	call := func(method, path, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	getStats := func() cacheStatsOut {
		t.Helper()
		rec := call(http.MethodGet, "/api/v1/cache/stats", env.jwtAdmin)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET stats = %d, тело %s", rec.Code, rec.Body.String())
		}
		var s cacheStatsOut
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Трафик: MISS + HIT по 7 байт (как в TestAdminCacheStatsLive).
	for range 2 {
		obj, _, err := engine.FetchStatus(t.Context(), eco, "/t/pkg/a.deb")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(obj.Body)
		_ = obj.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	before := getStats()
	if before.Hits < 1 || before.Packages < 1 {
		t.Fatalf("сброс при нулях ничего бы не доказал: %+v", before)
	}
	// POST reset → 204.
	if rec := call(http.MethodPost, "/api/v1/cache/stats/reset", env.jwtAdmin); rec.Code != http.StatusNoContent {
		t.Fatalf("POST reset = %d, хочу 204 (тело %s)", rec.Code, rec.Body.String())
	}
	if stats.calls != 1 {
		t.Errorf("ResetStats вызван %d раз, хочу 1", stats.calls)
	}
	// После сброса все нули (включая packages); per-eco строка живёт с нулями.
	after := getStats()
	if after.Hits != 0 || after.Misses != 0 || after.BytesFromUpstream != 0 || after.Packages != 0 {
		t.Errorf("после сброса не нули: %+v", after)
	}
	if len(after.PerEcosystem) != 1 || after.PerEcosystem[0].Ecosystem != "t" {
		t.Fatalf("per_ecosystem после сброса = %+v, хочу ряд t", after.PerEcosystem)
	}
	pe := after.PerEcosystem[0]
	if pe.Hits != 0 || pe.Misses != 0 || pe.Packages != 0 {
		t.Errorf("per-eco ряд после сброса = %+v, хочу нули", pe)
	}
	// Аудит: action=cache.stats.reset, result=ok (204).
	e := lastAudit(t, env.audit)
	if e.Action != "cache.stats.reset" || e.Result != domain.AuditOK {
		t.Errorf("аудит: %+v, хочу cache.stats.reset/ok", e)
	}
	// Идемпотентность: повторный POST — 204, сброс всё ещё полон.
	if rec := call(http.MethodPost, "/api/v1/cache/stats/reset", env.jwtAdmin); rec.Code != http.StatusNoContent {
		t.Fatalf("повторный POST reset = %d, хочу 204", rec.Code)
	}
	if again := getStats(); again.Hits != 0 || again.Packages != 0 {
		t.Errorf("повторный сброс испортил нули: %+v", again)
	}
}

// TestAdminCacheStatsResetDBFailure — сбой БД → 503 unavailable, атомики
// НЕ тронуты (полусброс хуже отсутствия сброса, сессия 97).
func TestAdminCacheStatsResetDBFailure(t *testing.T) {
	env := newAdminEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload")
	}))
	t.Cleanup(up.Close)
	engine := cacheengine.New(
		testutil.NewFakeStorage(env.clock), testutil.NewFakeObjectIndex(),
		up.Client(), env.clock, cacheengine.Config{}, nil,
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: time.Minute}
	stats := &resetCountingStats{FakeStatsStore: testutil.NewFakeStatsStore(), err: errors.New("db down")}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Clock: env.clock, Cache: engine, Stats: stats, Audit: env.audit,
		Ecosystems: map[string]port.Ecosystem{"t": eco},
	})
	obj, _, err := engine.FetchStatus(t.Context(), eco, "/t/pkg/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Второй запрос — HIT (как в TestAdminCacheStatsReset): сбой БД
	// проверяется при живых счётчиках, а не на нулях.
	obj, _, err = engine.FetchStatus(t.Context(), eco, "/t/pkg/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/cache/stats/reset", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("сбой БД = %d, хочу 503 (тело %s)", rec.Code, rec.Body.String())
	}
	var e apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "unavailable" {
		t.Fatalf("код = %q (тело %s), хочу unavailable", e.Code, rec.Body.String())
	}
	// Атомики живы: GET stats показывает трафик (сброс не начался).
	r = httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var s cacheStatsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Hits < 1 {
		t.Errorf("hits = %d, хочу >0 — атомики не должны сбрасываться при сбое БД", s.Hits)
	}
	// Неудачная мутация видна в трейле под настоящим именем (урок 87).
	ae := lastAudit(t, env.audit)
	if ae.Action != "cache.stats.reset" || ae.Result != "503" {
		t.Errorf("аудит: %+v, хочу cache.stats.reset/503", ae)
	}
}

// TestAdminCacheTransactions — живой разрез /api/v1/cache/transactions
// (сессия 100): трафик через движок отражается в истории newest-first,
// limit режет самые свежие, невалидный limit — 400, деградация без
// Cache — 200 []. Образец харнесса — TestAdminCacheStatsLive.
func TestAdminCacheTransactions(t *testing.T) {
	env := newAdminEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pkg/a.deb":
			_, _ = io.WriteString(w, "payload")
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(up.Close)
	engine := cacheengine.New(
		testutil.NewFakeStorage(env.clock), testutil.NewFakeObjectIndex(),
		up.Client(), env.clock, cacheengine.Config{}, nil,
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: time.Minute}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Clock: env.clock, Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"t": eco},
	})
	// Трафик: MISS + HIT + error (5xx), как в TestTxnHistory (сессия 99).
	for range 2 {
		obj, _, err := engine.FetchStatus(t.Context(), eco, "/t/pkg/a.deb")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(obj.Body)
		_ = obj.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := engine.FetchStatus(t.Context(), eco, "/t/pkg/broken.deb"); err == nil {
		t.Fatal("запрос 5xx — хочу ошибку")
	}
	call := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	// 1. Без limit: 3 записи newest-first, статусы верны.
	rec := call("/api/v1/cache/transactions")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var txns []txnOut
	if err := json.Unmarshal(rec.Body.Bytes(), &txns); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		path, status string
		err          bool
	}{
		{"/t/pkg/broken.deb", "error", true},
		{"/t/pkg/a.deb", "HIT", false},
		{"/t/pkg/a.deb", "MISS", false},
	}
	if len(txns) != len(want) {
		t.Fatalf("записей = %d, хочу %d: %+v", len(txns), len(want), txns)
	}
	for i, w := range want {
		got := txns[i]
		if got.Path != w.path || got.Status != w.status {
			t.Fatalf("запись %d = %q %q, хочу %q %q", i, got.Path, got.Status, w.path, w.status)
		}
		if got.Ecosystem != "t" {
			t.Errorf("запись %d: eco = %q, хочу %q", i, got.Ecosystem, "t")
		}
		if w.err && got.Error == "" {
			t.Errorf("запись %d: пустая ошибка у error-записи", i)
		}
		if !w.err && (got.Error != "" || got.Size <= 0) {
			t.Errorf("запись %d: error=%q size=%d, хочу пустую ошибку и размер >0", i, got.Error, got.Size)
		}
		if got.At.IsZero() {
			t.Errorf("запись %d: нулевое время", i)
		}
	}
	// 2. limit=2: две самые свежие записи.
	rec = call("/api/v1/cache/transactions?limit=2")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var two []txnOut
	if err := json.Unmarshal(rec.Body.Bytes(), &two); err != nil {
		t.Fatal(err)
	}
	if len(two) != 2 || two[0].Status != "error" || two[1].Status != "HIT" {
		t.Fatalf("limit=2: %+v, хочу [error HIT]", two)
	}
	// 3. Невалидный limit → 400 validation_error.
	for _, q := range []string{"abc", "0", "51"} {
		rec = call("/api/v1/cache/transactions?limit=" + q)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s = %d, хочу 400", q, rec.Code)
			continue
		}
		var e apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "validation_error" {
			t.Errorf("limit=%s: тело %s, хочу validation_error", q, rec.Body.String())
		}
	}
	// 4. Деградация: Deps без Cache → 200 [].
	degraded := BuildAdminRouter(Deps{Auth: env.auth, Clock: env.clock})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/cache/transactions", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	drec := httptest.NewRecorder()
	degraded.ServeHTTP(drec, r)
	if drec.Code != http.StatusOK {
		t.Fatalf("деградация = %d, хочу 200", drec.Code)
	}
	if got := strings.TrimRight(drec.Body.String(), "\n"); got != "[]" {
		t.Errorf("деградация: тело %q, хочу []", got)
	}
}

func TestAdminAuditPagination(t *testing.T) {
	env := newAdminEnv(t)
	// Пишем 100 записей напрямую в фейковый аудит.
	for i := 0; i < 100; i++ {
		if err := env.audit.Record(t.Context(), domain.AuditEntry{
			At: env.clock.Now(), Actor: "system", Action: "test.op",
			Object: "x", Result: domain.AuditOK,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Первая страница 40 записей.
	rec := callAdmin(env, http.MethodGet, "/api/v1/audit?limit=40", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var page1 []auditEntryOut
	if err := json.Unmarshal(rec.Body.Bytes(), &page1); err != nil {
		t.Fatal(err)
	}
	if len(page1) != 40 {
		t.Fatalf("страница 1 = %d записей, хочу 40", len(page1))
	}
	// Вторая страница — after_id = последний ID страницы 1.
	lastID := page1[len(page1)-1].ID
	rec = callAdmin(env, http.MethodGet, "/api/v1/audit?after_id="+itoa64(lastID)+"&limit=40", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var page2 []auditEntryOut
	if err := json.Unmarshal(rec.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2) != 40 {
		t.Fatalf("страница 2 = %d записей, хочу 40", len(page2))
	}
	// Третья страница — остаток (20).
	lastID = page2[len(page2)-1].ID
	rec = callAdmin(env, http.MethodGet, "/api/v1/audit?after_id="+itoa64(lastID)+"&limit=40", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var page3 []auditEntryOut
	if err := json.Unmarshal(rec.Body.Bytes(), &page3); err != nil {
		t.Fatal(err)
	}
	if len(page3) != 20 {
		t.Fatalf("страница 3 = %d записей, хочу 20", len(page3))
	}
	// Все ID уникальные и по возрастанию.
	all := append(append([]auditEntryOut{}, page1...), page2...)
	all = append(all, page3...)
	for i := 1; i < len(all); i++ {
		if all[i].ID <= all[i-1].ID {
			t.Errorf("ID не возрастает на %d: %d <= %d", i, all[i].ID, all[i-1].ID)
		}
	}
}

func TestAdminAuditDefaultLimit(t *testing.T) {
	env := newAdminEnv(t)
	// 5 записей, запрос без limit — fallback 100 (но вернутся все 5).
	for i := 0; i < 5; i++ {
		if err := env.audit.Record(t.Context(), domain.AuditEntry{Actor: "x", Action: "y", Object: "z", Result: domain.AuditOK}); err != nil {
			t.Fatal(err)
		}
	}
	rec := callAdmin(env, http.MethodGet, "/api/v1/audit", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var page []auditEntryOut
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page) != 5 {
		t.Errorf("default limit = %d записей, хочу 5", len(page))
	}
}

// TestAdminAuditMiddlewareRecordsMutations — проверка, что audit
// middleware автоматически пишет записи о не-GET мутациях.
func TestAdminAuditMiddlewareRecordsMutations(t *testing.T) {
	env := newAdminEnv(t)
	body := `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy"}`
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, env.jwtAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
	// Аудит должен был записать action «remote.create» от имени admin.
	entries, err := env.audit.AuditEntries(t.Context(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "remote.create" && e.Actor == "admin" && e.Result == domain.AuditOK {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("аудит не записал remote.create: %+v", entries)
	}
}

// TestAdminAuditMiddlewareSkipsGET — GET-запросы не пишутся в аудит.
func TestAdminAuditMiddlewareSkipsGET(t *testing.T) {
	env := newAdminEnv(t)
	callAdmin(env, http.MethodGet, "/api/v1/remotes", "", env.jwtAdmin)
	callAdmin(env, http.MethodGet, "/api/v1/audit", "", env.jwtAdmin)
	if env.audit.Len() != 0 {
		t.Errorf("GET записался в аудит: %d записей", env.audit.Len())
	}
}

// TestAdminMetricsEndpointBehindAuth — /metrics отдаёт 200 за admin
// token, 401 без auth.
func TestAdminMetricsEndpointBehindAuth(t *testing.T) {
	env := newAdminEnv(t)
	// Создаём новый роутер с MetricsHandler.
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Remotes: env.remotes, Audit: env.audit, Tasks: env.tasks, Clock: env.clock,
		MetricsHandler: metricsStub(),
	})
	// Без auth — 401.
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("metrics без auth = %d, хочу 401", rec.Code)
	}
	// С admin session — 200.
	r = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("metrics с admin session = %d, хочу 200", rec.Code)
	}
	// С admin api token — 200.
	r = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+env.apiAdmin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("metrics с admin api token = %d, хочу 200", rec.Code)
	}
	// С user role session — 403 (RequireAdmin rejects).
	r = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+env.jwtUser)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("metrics с user session = %d, хочу 403", rec.Code)
	}
}

// metricsStub — простой http.Handler, отдающий 200 OK; нужен только
// для проверки auth-матрицы /metrics без реального Prometheus.
func metricsStub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# HELP stub"))
	})
}

// lastAudit — последняя запись фейк-лога (по возрастанию ID).
func lastAudit(t *testing.T, log *testutil.FakeAuditLog) domain.AuditEntry {
	t.Helper()
	entries, err := log.AuditEntries(context.Background(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("аудит пуст")
	}
	return entries[len(entries)-1]
}

// TestAuditRejectedMutations — ядро сессии 37: отклонённые auth'ом
// мутации оставляют записи. 401 (кривой токен) → result="401",
// actor=anonymous; 403 (валидная сессия без прав) → result="403",
// actor=username.
func TestAuditRejectedMutations(t *testing.T) {
	env := newAdminEnv(t)
	// 401: POST /remotes с кривым bearer.
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", `{}`, "garbage")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("кривой токен = %d, хочу 401", rec.Code)
	}
	e := lastAudit(t, env.audit)
	if e.Result != "401" || e.Actor != "anonymous" {
		t.Errorf("401: result=%q actor=%q, хочу 401/anonymous", e.Result, e.Actor)
	}
	if e.Action != "create.remotes" {
		t.Errorf("401: action=%q, хочу create.remotes", e.Action)
	}
	// 403: валидная user-сессия на admin-only мутации.
	rec = callAdmin(env, http.MethodPost, "/api/v1/remotes", `{}`, env.jwtUser)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user-сессия на /remotes = %d, хочу 403", rec.Code)
	}
	e = lastAudit(t, env.audit)
	if e.Result != "403" || e.Actor != "user" {
		t.Errorf("403: result=%q actor=%q, хочу 403/user", e.Result, e.Actor)
	}
}

// TestAuditScopedTokenForbiddenOnForeignRepo — scoped-токен валиден,
// но не на это репо: 403 с actor=token:<prefix> (не anonymous —
// личность атакующего известна из токена).
func TestAuditScopedTokenForbiddenOnForeignRepo(t *testing.T) {
	// Свой auth-сервис: FixedRand в newRepoEnv один UUID — все токены
	// коллидируют по SHA256, TokenBySHA256 нашёл бы admin-токен.
	// Здесь Rand с двумя значениями: admin-токен и scoped различимы.
	users := testutil.NewFakeUserStore()
	tokens := &handlerTokens{}
	clock := testutil.NewManualClock(time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC))
	a, err := auth.New(auth.Config{
		Users: users, Tokens: tokens, Audit: nil, Revocations: testutil.NewFakeRevocations(),
		Clock: clock, Rand: testutil.FixedRand(
			"77777777-7777-4777-8777-777777777777",
			"88888888-8888-4888-8888-888888888888",
		),
		JWTSecret: "secret", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.CreateUser(t.Context(), "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	jwtAdmin, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	// Репо 1 существует (чужой путь — репо 2 — отвергается по scope
	// до владельческого lookup).
	_, scoped, err := a.IssueAPIToken(t.Context(), admin, "scoped", []domain.Scope{"repo:1:write"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	auditLog := testutil.NewFakeAuditLog()
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Repos: testutil.NewFakeRepoStore(), Audit: auditLog,
		Tasks: NewTaskRegistry(2, clock, nil), Publish: nil, Clock: clock,
	})
	// Санити: admin-токен и scoped различимы (разные SHA256).
	req := httptest.NewRequest(http.MethodPut, "/api/v1/repos/2/objects/pool/x.deb", strings.NewReader("x"))
	req.ContentLength = 1
	req.Header.Set("Authorization", "Bearer "+scoped)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped-токен в чужое репо = %d, хочу 403, тело %q (админ JWT %q)", rec.Code, rec.Body.String(), jwtAdmin)
	}
	entries, err := auditLog.AuditEntries(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("аудит пуст")
	}
	e := entries[len(entries)-1]
	if e.Result != "403" {
		t.Errorf("result=%q, хочу 403", e.Result)
	}
	if !strings.HasPrefix(e.Actor, "token:") || e.Actor == "token:" {
		t.Errorf("actor=%q, хочу token:<prefix>", e.Actor)
	}
	if !strings.HasPrefix(e.Action, "update.repos.objects") {
		t.Errorf("action=%q, хочу update.repos.objects*", e.Action)
	}
}

// TestAuditLogoutAndSetup — security-события: logout (успешный и
// отклонённый) и setup-попытки (брутфорс X-Setup-Token) аудируются.
func TestAuditLogoutAndSetup(t *testing.T) {
	env := newAdminEnv(t)
	// Успешный logout — auth.logout от username сессии.
	rec := callAdmin(env, http.MethodPost, "/api/v1/auth/logout", "", env.jwtAdmin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	e := lastAudit(t, env.audit)
	if e.Action != "auth.logout" || e.Actor != "admin" || e.Result != domain.AuditOK {
		t.Errorf("logout: %+v", e)
	}
	// Logout с кривым токеном — 401, но запись есть.
	rec = callAdmin(env, http.MethodPost, "/api/v1/auth/logout", "", "garbage")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout с кривым токеном = %d, хочу 401", rec.Code)
	}
	e = lastAudit(t, env.audit)
	if e.Action != "auth.logout" || e.Result != "401" || e.Actor != "anonymous" {
		t.Errorf("logout 401: %+v", e)
	}
	// Setup-брутфорс: кривой X-Setup-Token → 403 + запись.
	// Bootstrap-окно уже закрыто (в env создан admin), ставим SetupToken.
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Remotes: env.remotes, Audit: env.audit, Tasks: env.tasks, Clock: env.clock,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/setup", strings.NewReader(`{"username":"hacker","password":"password"}`))
	r.RemoteAddr = "10.0.0.7:1"
	r.Header.Set("X-Setup-Token", "wrong")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("setup с кривым токеном = %d, хочу 403", rec2.Code)
	}
	e = lastAudit(t, env.audit)
	if e.Action != "setup" || e.Result != "403" || e.Actor != "bootstrap" {
		t.Errorf("setup 403: %+v", e)
	}
}

// itoa64 — локальный strconv.FormatInt (без импорта ради одной строки).
func itoa64(n int64) string {
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

// TestUserAuditActionsUnified — сессия 63: движок и middleware пишут
// операцию под одним именем. Action ставится до вызова движка (паттерн
// гранта, сессия 58): отклонённая мутация уходила под fallback
// create.users и трейл показывал два имени одной операции.
func TestUserAuditActionsUnified(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	auditLog := testutil.NewFakeAuditLog()
	a, err := auth.New(auth.Config{
		Users: testutil.NewFakeUserStore(), Tokens: &handlerTokens{}, Audit: auditLog,
		Revocations: testutil.NewFakeRevocations(), Clock: clock,
		Rand:      testutil.FixedRand("44444444-4444-4444-8444-444444444444"),
		JWTSecret: "secret", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.CreateUser(t.Context(), "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	jwtAdmin, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Audit: auditLog, Clock: clock,
	})
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtAdmin)
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := call(http.MethodPost, "/api/v1/users", `{"username":"bob","password":"password","role":"user"}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /users = %d, хочу 201 (тело %s)", rec.Code, rec.Body.String())
	}
	// Отклонённая мутация тоже под user.create (с кодом результата),
	// не под fallback create.users.
	if rec := call(http.MethodPost, "/api/v1/users", `{"username":"bad name","password":"password"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /users (кривое имя) = %d, хочу 400 (тело %s)", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodDelete, "/api/v1/users/2", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /users/2 = %d, хочу 204 (тело %s)", rec.Code, rec.Body.String())
	}
	entries, err := auditLog.AuditEntries(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Объект различает писца: «user:bob»/«user:2» у движка, путь запроса
	// у middleware.
	want := map[[3]string]bool{
		{"user.create", "user:bob", domain.AuditOK}:      false,
		{"user.create", "/api/v1/users", domain.AuditOK}: false,
		// 400 вне статус-словаря (аудит 2026-08-30) → result=error.
		{"user.create", "/api/v1/users", domain.AuditError}: false,
		{"user.delete", "user:2", domain.AuditOK}:           false,
		{"user.delete", "/api/v1/users/2", domain.AuditOK}:  false,
	}
	for _, e := range entries {
		key := [3]string{e.Action, e.Object, e.Result}
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if e.Action == "create.users" || e.Action == "delete.users" {
			t.Errorf("fallback-имя %q в трейле: %+v", e.Action, e)
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("нет записи %v — операция ушла под другое имя", key)
		}
	}
}

// TestRemoteAuditActionsUnified — сессия 68: remote.* action ставится
// до вызова каталога (паттерн user.create, сессия 63): отклонённая
// мутация писалась бы middleware под fallback-именем create.remotes —
// два имени одной операции в трейле.
func TestRemoteAuditActionsUnified(t *testing.T) {
	env := newAdminEnv(t)
	body := `{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy"}`
	if rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, env.jwtAdmin); rec.Code != http.StatusCreated {
		t.Fatalf("POST /remotes = %d, хочу 201 (тело %s)", rec.Code, rec.Body.String())
	}
	// Дубль имени → 409: запись под remote.create (result=409),
	// не под fallback create.remotes.
	if rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, env.jwtAdmin); rec.Code != http.StatusConflict {
		t.Fatalf("повторный POST /remotes = %d, хочу 409 (тело %s)", rec.Code, rec.Body.String())
	}
	if rec := callAdmin(env, http.MethodDelete, "/api/v1/remotes/1", "", env.jwtAdmin); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /remotes/1 = %d, хочу 204 (тело %s)", rec.Code, rec.Body.String())
	}
	// Удаление несуществующего → 404 под тем же remote.delete.
	if rec := callAdmin(env, http.MethodDelete, "/api/v1/remotes/1", "", env.jwtAdmin); rec.Code != http.StatusNotFound {
		t.Fatalf("повторный DELETE /remotes/1 = %d, хочу 404 (тело %s)", rec.Code, rec.Body.String())
	}
	entries, err := env.audit.AuditEntries(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := map[[2]string]bool{
		{"remote.create", domain.AuditOK}: false,
		{"remote.create", "409"}:          false,
		{"remote.delete", domain.AuditOK}: false,
		{"remote.delete", "404"}:          false,
	}
	for _, e := range entries {
		key := [2]string{e.Action, e.Result}
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if e.Action == "create.remotes" || e.Action == "delete.remotes" {
			t.Errorf("fallback-имя %q в трейле: %+v", e.Action, e)
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("нет записи %v — операция ушла под другое имя", key)
		}
	}
}
