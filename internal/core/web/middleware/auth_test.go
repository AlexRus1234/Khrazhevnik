package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/testutil"
)

type middlewareTokens struct {
	token   domain.APIToken
	hashErr error
}

func (s *middlewareTokens) CreateToken(_ context.Context, t domain.APIToken) (domain.APIToken, error) {
	t.ID = 1
	s.token = t
	return t, nil
}
func (s *middlewareTokens) TokenBySHA256(_ context.Context, h string) (domain.APIToken, error) {
	if s.hashErr != nil {
		return domain.APIToken{}, s.hashErr
	}
	if s.token.SHA256 == h {
		return s.token, nil
	}
	return domain.APIToken{}, &domain.NotFoundError{}
}
func (s *middlewareTokens) TokensByUser(context.Context, int64) ([]domain.APIToken, error) {
	return []domain.APIToken{s.token}, nil
}
func (s *middlewareTokens) DeleteToken(context.Context, int64) error            { return nil }
func (s *middlewareTokens) RevokeToken(context.Context, int64, time.Time) error { return nil }
func (s *middlewareTokens) TouchToken(context.Context, int64, time.Time) error  { return nil }

func middlewareAuth(t *testing.T) (*auth.Service, *testutil.FakeUserStore, string, string) {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tokens := &middlewareTokens{}
	a, err := auth.New(auth.Config{Users: users, Tokens: tokens, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("22222222-2222-4222-8222-222222222222"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.CreateUser(context.Background(), "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := a.CreateUser(context.Background(), "user", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	jwtRaw, err := a.IssueSession(context.Background(), admin)
	if err != nil {
		t.Fatal(err)
	}
	_, apiRaw, err := a.IssueAPIToken(context.Background(), user, "repo", []domain.Scope{"repo:7:write"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return a, users, jwtRaw, apiRaw
}

func middlewareRequest(raw string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if raw != "" {
		r.Header.Set("Authorization", "Bearer "+raw)
	}
	return r
}

// failingUserStore — чтение пользователя всегда падает транзиентной
// ошибкой (не NotFound): остальное — поведение фейка.
type failingUserStore struct {
	*testutil.FakeUserStore
	err error
}

func (s *failingUserStore) User(context.Context, int64) (domain.User, error) {
	return domain.User{}, s.err
}
func (s *failingUserStore) UserByUsername(context.Context, string) (domain.User, error) {
	return domain.User{}, s.err
}

// TestAuthMiddlewareCatalogFailure — сбой каталога при валидном
// предъявленном токене — 503, а не 401 (аудит 2026-08-27: сбой БД
// не должен выглядеть как «неверные учётные данные»).
func TestAuthMiddlewareCatalogFailure(t *testing.T) {
	users := &failingUserStore{FakeUserStore: testutil.NewFakeUserStore(), err: errors.New("db down")}
	tokens := &middlewareTokens{hashErr: errors.New("db down")}
	a, err := auth.New(auth.Config{Users: users, Tokens: tokens, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("22222222-2222-4222-8222-222222222222"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	admin := domain.User{ID: 1, Username: "admin", Role: domain.RoleAdmin, TokenVersion: 1}
	jwtRaw, err := a.IssueSession(context.Background(), admin)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	w := httptest.NewRecorder()
	RequireSession(a)(next).ServeHTTP(w, middlewareRequest(jwtRaw))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("session при сбое каталога = %d, хочу 503", w.Code)
	}
	w = httptest.NewRecorder()
	RequireAPIToken(a)(next).ServeHTTP(w, middlewareRequest("khz_dead_beef"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("api-token при сбое каталога = %d, хочу 503", w.Code)
	}
}

func TestAuthMiddlewareUnauthorizedAndAdmin(t *testing.T) {
	a, users, jwtRaw, _ := middlewareAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, tc := range []struct {
		name, raw string
		want      int
	}{{"missing", "", 401}, {"malformed", "not.jwt", 401}, {"api-as-jwt", "khz_bad_x", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			RequireSession(a)(next).ServeHTTP(w, middlewareRequest(tc.raw))
			if w.Code != tc.want {
				t.Fatalf("status = %d", w.Code)
			}
		})
	}
	w := httptest.NewRecorder()
	RequireSession(a)(RequireAdmin(next)).ServeHTTP(w, middlewareRequest(jwtRaw))
	if w.Code != 204 {
		t.Fatalf("admin = %d", w.Code)
	}
	u, _ := users.User(context.Background(), 1)
	u.Role = domain.RoleUser
	_ = users.UpdateUser(context.Background(), u)
	w = httptest.NewRecorder()
	RequireSession(a)(RequireAdmin(next)).ServeHTTP(w, middlewareRequest(jwtRaw))
	if w.Code != 403 {
		t.Fatalf("changed role = %d", w.Code)
	}
}

// Даунгрейд владельца admin-scope токена (сессия 67): запрос с этим
// токеном отклоняется. Отлуп — 401 по контракту authReject (Forbidden
// от VerifyAPIToken не раскрывает валидность токена; 403 здесь был бы
// сигналом «токен жив»), в отличие от 403 RequireAdmin для опознанной
// сессии.
func TestRequireAPITokenAdminScopeAfterOwnerDowngrade(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	a, err := auth.New(auth.Config{Users: users, Tokens: &middlewareTokens{}, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("22222222-2222-4222-8222-222222222222"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.CreateUser(ctx, "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := a.IssueAPIToken(ctx, admin, "ci", []domain.Scope{domain.ScopeAdmin}, 0)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	w := httptest.NewRecorder()
	RequireAPIToken(a)(next).ServeHTTP(w, middlewareRequest(raw))
	if w.Code != http.StatusNoContent {
		t.Fatalf("admin-токен у админа = %d, хочу 204", w.Code)
	}
	admin.Role = domain.RoleUser
	if err := users.UpdateUser(ctx, admin); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	RequireAPIToken(a)(next).ServeHTTP(w, middlewareRequest(raw))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("admin-токен после даунгрейда владельца = %d, хочу 401", w.Code)
	}
}

func TestAPIMiddlewareAndScopeMatrix(t *testing.T) {
	a, _, jwtRaw, apiRaw := middlewareAuth(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, raw := range []string{"", "khz_bad_x", apiRaw + "x"} {
		w := httptest.NewRecorder()
		RequireAPIToken(a)(next).ServeHTTP(w, middlewareRequest(raw))
		if w.Code != 401 {
			t.Errorf("API %q = %d", raw, w.Code)
		}
	}
	for _, tc := range []struct {
		scope domain.Scope
		want  int
	}{{"repo:7:write", 204}, {"repo:8:write", 403}, {domain.ScopeAdmin, 403}} {
		w := httptest.NewRecorder()
		RequireAPIToken(a)(RequireScope(tc.scope)(next)).ServeHTTP(w, middlewareRequest(apiRaw))
		if w.Code != tc.want {
			t.Errorf("scope %q = %d", tc.scope, w.Code)
		}
	}
	for _, scope := range []domain.Scope{"repo:8:write", domain.ScopeAdmin} {
		w := httptest.NewRecorder()
		RequireSession(a)(RequireScope(scope)(next)).ServeHTTP(w, middlewareRequest(jwtRaw))
		if w.Code != 204 {
			t.Errorf("admin scope %q = %d", scope, w.Code)
		}
	}
	w := httptest.NewRecorder()
	RequireScope("repo:1:write")(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 403 {
		t.Fatalf("missing context = %d", w.Code)
	}
}
