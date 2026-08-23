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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
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
		Users: users, Tokens: tokens, Audit: nil,
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
	tasks := NewTaskRegistry(2, clock)
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Remotes: remotes, Audit: auditLog, Tasks: tasks, Clock: clock,
	})
	return &adminEnv{
		handler: h, auth: a, remotes: remotes, audit: auditLog,
		tasks: tasks, clock: clock,
		jwtAdmin: jwtAdmin, jwtUser: jwtUser, apiAdmin: apiAdmin,
	}
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
