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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	authmw "khrazhevnik/internal/core/web/middleware"
	"khrazhevnik/internal/testutil"
)

func TestActionFromRequest(t *testing.T) {
	for _, tc := range []struct {
		method, path, want string
	}{
		{http.MethodPost, "/api/v1/remotes", "create.remotes"},
		{http.MethodPatch, "/api/v1/remotes/42", "update.remotes"},
		{http.MethodDelete, "/api/v1/remotes/42", "delete.remotes"},
		{http.MethodPost, "/api/v1/users/2/api-tokens", "create.users.api-tokens"},
		{http.MethodPost, "/api/v1/setup", "create.setup"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if got := actionFromRequest(r); got != tc.want {
			t.Errorf("%s %s → %q, хочу %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestAuditMiddlewareWritesResultByStatus(t *testing.T) {
	log := testutil.NewFakeAuditLog()
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		switch r.URL.Path {
		case "/api/v1/fail":
			status = http.StatusBadRequest
		case "/api/v1/rejected":
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
	})
	h := AuditMiddleware(log, clock)(next)

	// OK — result=ok.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/x", nil))
	if log.Len() != 1 {
		t.Fatalf("записей = %d, хочу 1", log.Len())
	}
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if entries[0].Result != domain.AuditOK {
		t.Errorf("OK result = %q", entries[0].Result)
	}

	// 403 — result="403" (код статуса, аудит 2026-08-30).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rejected", nil))
	entries, _ = log.AuditEntries(context.Background(), 0, 10)
	if entries[1].Result != "403" {
		t.Errorf("403 result = %q, хочу \"403\"", entries[1].Result)
	}

	// 4xx без явного словаря — result=error.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fail", nil))
	entries, _ = log.AuditEntries(context.Background(), 0, 10)
	if entries[2].Result != domain.AuditError {
		t.Errorf("400 result = %q, хочу error", entries[2].Result)
	}

	// GET — без аудита.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil))
	if log.Len() != 3 {
		t.Errorf("GET записался в аудит: %d", log.Len())
	}
}

func TestAuditMiddlewareActorFromAuthContext(t *testing.T) {
	log := testutil.NewFakeAuditLog()
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := AuditMiddleware(log, clock)(next)
	// Кладём user в контекст через middleware-ключ (как RequireSession).
	r := httptest.NewRequest(http.MethodPost, "/api/v1/remotes", nil)
	r = r.WithContext(authmw.WithUserContext(r.Context(), domain.User{ID: 1, Username: "alice"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if len(entries) != 1 || entries[0].Actor != "alice" {
		t.Errorf("actor = %q, хочу alice", entries[0].Actor)
	}
}

func TestAuditMiddlewareNilLogIsSafe(t *testing.T) {
	clock := testutil.NewManualClock(time.Unix(0, 0))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := AuditMiddleware(nil, clock)(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/x", nil))
	if rec.Code != 200 {
		t.Errorf("nil AuditLog сломал запрос: %d", rec.Code)
	}
}

func TestWithAuditActionAndDetail(t *testing.T) {
	log := testutil.NewFakeAuditLog()
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithAuditAction(r.Context(), "custom.action")
		ctx = WithAuditDetail(ctx, "extra-info")
		*r = *r.WithContext(ctx)
		w.WriteHeader(http.StatusOK)
	})
	h := AuditMiddleware(log, clock)(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/x", nil))
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if len(entries) != 1 {
		t.Fatal("запись не создана")
	}
	if entries[0].Action != "custom.action" {
		t.Errorf("action = %q, хочу custom.action", entries[0].Action)
	}
	if entries[0].Detail != "extra-info" {
		t.Errorf("detail = %q, хочу extra-info", entries[0].Detail)
	}
}

func TestStatusForMapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
		code string
	}{
		{nil, http.StatusOK, ""},
		{&domain.NotFoundError{What: "x", Key: "y"}, http.StatusNotFound, "not_found"},
		{&domain.ConflictError{What: "x", Key: "y"}, http.StatusConflict, "conflict"},
		{&domain.ForbiddenError{Reason: "z"}, http.StatusForbidden, "forbidden"},
		{&domain.UnavailableError{What: "x", Reason: "z"}, http.StatusServiceUnavailable, "unavailable"},
		{&domain.ValidationError{What: "x"}, http.StatusBadRequest, "validation_error"},
		{&domain.TooLargeError{Size: 100, Limit: 50}, http.StatusRequestEntityTooLarge, "too_large"},
		{&domain.StaleError{Have: "a", Want: "b"}, http.StatusConflict, "stale"},
		{ErrTaskDuplicate, http.StatusConflict, "task_duplicate"},
		{ErrTaskLimit, http.StatusTooManyRequests, "task_limit"},
	} {
		status, code := statusFor(tc.err)
		if status != tc.want || code != tc.code {
			t.Errorf("%v → %d/%q, хочу %d/%q", tc.err, status, code, tc.want, tc.code)
		}
	}
}

// slowAuditLog — фейк, читающий контекст: до отмены записи не
// принимает (имитация медленного каталога), после отмены — падает,
// как любой честный store с ctx.
type slowAuditLog struct {
	testutil.FakeAuditLog
}

func (s *slowAuditLog) Record(ctx context.Context, e domain.AuditEntry) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(50 * time.Millisecond):
		return s.FakeAuditLog.Record(ctx, e)
	}
}

// TestAuditRecordSurvivesCancelledContext — ядро сессии 37: отмена
// r.Context() до Record (клиент оборвал соединение посреди мутации)
// не должна терять запись аудита — WithoutCancel + свой таймаут.
func TestAuditRecordSurvivesCancelledContext(t *testing.T) {
	log := &slowAuditLog{}
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := AuditMiddleware(log, clock)(next)
	// Отменённый контекст, как у мёртвого соединения.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/remotes", nil).WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if log.Len() != 1 {
		t.Fatalf("отмена контекста потеряла запись аудита: %d", log.Len())
	}
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if entries[0].Action != "create.remotes" {
		t.Errorf("action = %q", entries[0].Action)
	}
}

// TestAuditMiddlewareRecordsPanic — паника хендлера мутации: запись
// result=500 остаётся, паника прокидывается наружу (её ловит Recoverer).
func TestAuditMiddlewareRecordsPanic(t *testing.T) {
	log := testutil.NewFakeAuditLog()
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler exploded")
	})
	h := AuditMiddleware(log, clock)(next)
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("middleware проглотил панику — Recoverer выше не ответит 500")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/remotes", nil))
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if len(entries) != 1 || entries[0].Result != "500" {
		t.Fatalf("паника не записана как 500: %+v", entries)
	}
}

// hangingAuditLog — фейк, чей Record держит 5s при живом контексте:
// имитация висящего каталога (уважающий ctx медленный store).
type hangingAuditLog struct {
	testutil.FakeAuditLog
}

func (h *hangingAuditLog) Record(ctx context.Context, e domain.AuditEntry) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return h.FakeAuditLog.Record(ctx, e)
	}
}

// Паника при висящем каталоге: сокращённый паник-таймаут (1s) отвечает
// клиенту (500 от Recoverer'а) существенно раньше обычного 5s-потолка —
// после смерти хендлера ждать запись некому.
func TestAuditPanicRecordTimeoutShort(t *testing.T) {
	log := &hangingAuditLog{}
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	h := AuditMiddleware(log, clock)(next)
	start := time.Now()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("middleware проглотил панику — Recoverer выше не ответит 500")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/x", nil))
	}()
	if elapsed := time.Since(start); elapsed >= auditRecordTimeout {
		t.Fatalf("паника держала ответ %v — паник-ветка пишет с обычным 5s-потолком", elapsed)
	}
}

// TestAuditActorFromRejectedAuth — actor опознан-но-отклонён:
// WithAuditActor (кладут auth-middleware при 403) виден recordAudit'у
// и перекрывает остаточный auth-контекст (reject-ветки затирают user
// заглушкой — Username пуст, маркер приоритетнее).
func TestAuditActorFromRejectedAuth(t *testing.T) {
	log := testutil.NewFakeAuditLog()
	clock := testutil.NewManualClock(time.Unix(1000, 0))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	h := AuditMiddleware(log, clock)(next)
	// Только маркер отклонённого (auth-контекста нет) → actor = маркер.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/repos/7/objects/x", nil)
	r = r.WithContext(authmw.WithAuditActor(r.Context(), "token:deadbeef"))
	h.ServeHTTP(httptest.NewRecorder(), r)
	// Реальная механика reject'а: user-контекст затёрт заглушкой
	// (как в RequireRepoAccess), поверх — маркер.
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/repos/7/objects/x", nil)
	ctx := authmw.WithUserContext(r2.Context(), domain.User{})
	ctx = authmw.WithAuditActor(ctx, "token:deadbeef")
	r2 = r2.WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), r2)
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(entries))
	}
	if entries[0].Actor != "token:deadbeef" {
		t.Errorf("actor отклонённого = %q, хочу token:deadbeef", entries[0].Actor)
	}
	if entries[1].Actor != "token:deadbeef" {
		t.Errorf("actor после затирания user = %q, хочу token:deadbeef", entries[1].Actor)
	}
}

// TestRepoAccessOutageAudits503 — сбой каталога в owner-ветке
// RequireRepoAccess (сессия 80): ответ 503, audit-запись result=503,
// actor — опознанная сессия (аутентификация прошла; 503 — не отказ
// в правах, «403 от alice» дезинформировал бы трейл).
func TestRepoAccessOutageAudits503(t *testing.T) {
	users := testutil.NewFakeUserStore()
	a, err := auth.New(auth.Config{
		Users: users, Tokens: &handlerTokens{}, Audit: nil,
		Revocations: testutil.NewFakeRevocations(),
		Clock:       testutil.NewManualClock(time.Unix(1000, 0)),
		Rand:        testutil.FixedRand("55555555-5555-4555-8555-555555555555"),
		JWTSecret:   "secret", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := a.CreateUser(context.Background(), "alice", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	jwtUser, err := a.IssueSession(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	repos := &failingRepoStore{
		RepoStore: testutil.NewFakeRepoStore(),
		err:       &domain.UnavailableError{What: "каталог", Reason: "сбой БД"},
	}
	log := testutil.NewFakeAuditLog()
	reached := false
	h := AuditMiddleware(log, testutil.NewManualClock(time.Unix(1000, 0)))(
		authmw.RequireRepoAccess(a, repos)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})))
	r := httptest.NewRequest(http.MethodPut, "/api/v1/repos/1/objects/pkg.deb", nil)
	r.Header.Set("Authorization", "Bearer "+jwtUser)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("сбой каталога = %d, хочу 503", rec.Code)
	}
	if reached {
		t.Fatal("хендлер выполнился при сбое каталога")
	}
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	if len(entries) != 1 {
		t.Fatalf("записей аудита = %d, хочу 1", len(entries))
	}
	if entries[0].Result != "503" {
		t.Errorf("result = %q, хочу 503", entries[0].Result)
	}
	if entries[0].Actor != "alice" {
		t.Errorf("actor = %q, хочу alice", entries[0].Actor)
	}
}
