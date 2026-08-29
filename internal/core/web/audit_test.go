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

	"khrazhevnik/internal/core/domain"
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
		if r.URL.Path == "/api/v1/fail" {
			status = http.StatusBadRequest
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

	// 4xx — result=error.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fail", nil))
	entries, _ = log.AuditEntries(context.Background(), 0, 10)
	if entries[1].Result != domain.AuditError {
		t.Errorf("400 result = %q", entries[1].Result)
	}

	// GET — без аудита.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil))
	if log.Len() != 2 {
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
