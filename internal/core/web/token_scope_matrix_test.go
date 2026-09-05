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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/testutil"

	"github.com/prometheus/client_golang/prometheus"
)

// Матрица «владелец × scopes × эндпоинт» (сессия 75, слепая зона
// middleware-тестов): API-токен авторизует ровно своими scopes, даже
// когда его владелец — админ. Раньше role-фастпас в RequireScope стоял
// до проверки scopes, и repo-scoped токен админа проходил
// RequireAdminOrAPIToken на весь admin-API.
type scopeMatrixEnv struct {
	handler  http.Handler
	jwtAdmin string
	// adminAdminToken — literal admin-scope у админа.
	adminAdminToken string
	// adminRepoToken — repo-scoped токен АДМИНА (владелец-админ,
	// scopes repo:1:write): утечка не должна открывать admin-API.
	adminRepoToken string
	// ciRepoToken — repo-scoped токен не-админа.
	ciRepoToken string
	// ciAdminToken — admin-scope токен не-админа: гасится движком
	// (сессия 67), до RequireScope не доходит.
	ciAdminToken string
}

func newScopeMatrixEnv(t *testing.T) *scopeMatrixEnv {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tokens := &handlerTokens{}
	clock := testutil.NewManualClock(time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))
	// Пять различных UUID: сессия + четыре токена. Один FixedRand на
	// все выпуски дал бы всем токенам одинаковый secret (одинаковый
	// SHA256) — lookup в фейке стал бы недетерминированным.
	a, err := auth.New(auth.Config{
		Users: users, Tokens: tokens, Audit: nil, Revocations: testutil.NewFakeRevocations(),
		Clock: clock,
		Rand: testutil.FixedRand(
			"11111111-1111-4111-8111-111111111111",
			"22222222-2222-4222-8222-222222222222",
			"33333333-3333-4333-8333-333333333333",
			"44444444-4444-4444-8444-444444444444",
			"55555555-5555-4555-8555-555555555555",
			"66666666-6666-4666-8666-666666666666",
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
	ci, err := a.CreateUser(t.Context(), "ci", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	jwtAdmin, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	_, adminAdmin, err := a.IssueAPIToken(t.Context(), admin, "ops", []domain.Scope{domain.ScopeAdmin}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, adminRepo, err := a.IssueAPIToken(t.Context(), admin, "ci", []domain.Scope{"repo:1:write"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, ciRepo, err := a.IssueAPIToken(t.Context(), ci, "ci", []domain.Scope{"repo:1:write"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, ciAdmin, err := a.IssueAPIToken(t.Context(), ci, "grab", []domain.Scope{domain.ScopeAdmin}, 0)
	if err != nil {
		t.Fatal(err)
	}
	repos := testutil.NewFakeRepoStore()
	if _, err := repos.CreateRepo(t.Context(), domain.Repo{Name: "tools", OwnerID: admin.ID, Ecosystem: "apt"}); err != nil {
		t.Fatal(err)
	}
	storage := testutil.NewFakeStorage(clock)
	publish := newPublishStub(storage)
	mh := metrics.NewHandler(metrics.NewCache(), prometheus.NewRegistry())
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Repos: repos, Storage: storage, Audit: testutil.NewFakeAuditLog(),
		Tasks: NewTaskRegistry(2, clock, nil), Publish: publish, Clock: clock,
		MetricsHandler: mh.MetricsHandler(),
	})
	return &scopeMatrixEnv{
		handler: h, jwtAdmin: jwtAdmin,
		adminAdminToken: adminAdmin, adminRepoToken: adminRepo,
		ciRepoToken: ciRepo, ciAdminToken: ciAdmin,
	}
}

func callScopeMatrix(env *scopeMatrixEnv, path, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "10.0.0.9:1"
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, r)
	return rec
}

func TestTokenScopeIdentityMatrix(t *testing.T) {
	env := newScopeMatrixEnv(t)
	for _, tc := range []struct {
		name, path, bearer string
		want               int
	}{
		// Слепая зона: repo-scoped токен админа НЕ проходит admin-API.
		{"admin-repo-token-users", "/api/v1/users", env.adminRepoToken, http.StatusForbidden},
		{"admin-repo-token-metrics", "/metrics", env.adminRepoToken, http.StatusForbidden},
		// ... но repo-ветка publish живёт своими scopes.
		{"admin-repo-token-objects", "/api/v1/repos/1/objects", env.adminRepoToken, http.StatusOK},
		// Literal admin-scope и сессия админа — не сломали.
		{"admin-token-users", "/api/v1/users", env.adminAdminToken, http.StatusOK},
		{"admin-session-users", "/api/v1/users", env.jwtAdmin, http.StatusOK},
		{"admin-token-metrics", "/metrics", env.adminAdminToken, http.StatusOK},
		// /metrics: repo-scoped токен не-админа — 403.
		{"ci-repo-token-metrics", "/metrics", env.ciRepoToken, http.StatusForbidden},
		// admin-scope у не-админа гасится VerifyAPIToken (сессия 67):
		// отлуп по контракту authReject — 401, а не 403 (403 раскрывал
		// бы валидность токена; постамбула сессии 67).
		{"ci-admin-token-users", "/api/v1/users", env.ciAdminToken, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := callScopeMatrix(env, tc.path, tc.bearer); rec.Code != tc.want {
				t.Fatalf("%s %s = %d, хочу %d, тело %s", tc.name, tc.path, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
