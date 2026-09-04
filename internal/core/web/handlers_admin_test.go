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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
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
