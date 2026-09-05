package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/testutil"
)

func handlerAuth(t *testing.T) (*auth.Service, *testutil.FakeUserStore) {
	t.Helper()
	users := testutil.NewFakeUserStore()
	a, err := auth.New(auth.Config{Users: users, Tokens: &handlerTokens{}, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("33333333-3333-4333-8333-333333333333"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return a, users
}

type handlerTokens struct {
	next   int64
	values map[int64]domain.APIToken
}

func (s *handlerTokens) CreateToken(_ context.Context, v domain.APIToken) (domain.APIToken, error) {
	if s.values == nil {
		s.values = map[int64]domain.APIToken{}
	}
	s.next++
	v.ID = s.next
	s.values[v.ID] = v
	return v, nil
}
func (s *handlerTokens) TokenBySHA256(_ context.Context, h string) (domain.APIToken, error) {
	for _, v := range s.values {
		if v.SHA256 == h {
			return v, nil
		}
	}
	return domain.APIToken{}, &domain.NotFoundError{}
}
func (s *handlerTokens) TokensByUser(_ context.Context, id int64) ([]domain.APIToken, error) {
	var out []domain.APIToken
	for _, v := range s.values {
		if v.UserID == id {
			out = append(out, v)
		}
	}
	return out, nil
}
func (s *handlerTokens) DeleteToken(context.Context, int64) error { return nil }
func (s *handlerTokens) RevokeToken(_ context.Context, id int64, at time.Time) error {
	v := s.values[id]
	v.RevokedAt = at
	s.values[id] = v
	return nil
}
func (s *handlerTokens) TouchToken(context.Context, int64, time.Time) error { return nil }

func callJSON(h http.Handler, method, path, remote, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remote
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func responseMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuthHandlersEndToEnd(t *testing.T) {
	a, _ := handlerAuth(t)
	h := BuildAdminRouter(Deps{Auth: a, SetupToken: "setup"})
	setup := `{"username":"admin","password":"password"}`
	if w := callJSON(h, http.MethodPost, "/api/v1/setup", "10.0.0.1:1", setup, ""); w.Code != 403 {
		t.Fatalf("setup without token = %d", w.Code)
	}
	// The setup token must be present on the request before serving.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/setup", strings.NewReader(setup))
	r.Header.Set("X-Setup-Token", "setup")
	r.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 201 {
		t.Fatalf("setup = %d", rec.Code)
	}
	if w := callJSON(h, http.MethodPost, "/api/v1/setup", "10.0.0.1:1", setup, ""); w.Code != 403 {
		t.Fatalf("repeat setup = %d", w.Code)
	}
	login := func(password, ip string) *httptest.ResponseRecorder {
		return callJSON(h, http.MethodPost, "/api/v1/auth/login", ip, `{"username":"admin","password":"`+password+`"}`, "")
	}
	for i := 0; i < 9; i++ {
		if login("bad", "10.0.0.2:1").Code != 401 {
			t.Fatal("failed login status")
		}
	}
	lw := login("password", "10.0.0.2:1")
	if lw.Code != 200 {
		t.Fatalf("login = %d", lw.Code)
	}
	session := responseMap(t, lw)["token"].(string)
	for i := 0; i < 10; i++ {
		if login("bad", "10.0.0.2:1").Code != 401 {
			t.Fatal("reset did not clear limiter")
		}
	}
	if login("bad", "10.0.0.2:1").Code != 429 {
		t.Fatal("rate limit missing")
	}
	if len(usersByID(t, a, 1)) != 1 {
		t.Fatal("setup user missing")
	}
	if w := callJSON(h, http.MethodGet, "/api/v1/users/", "10.0.0.3:1", "", session); w.Code != 200 {
		t.Fatalf("users = %d", w.Code)
	}
	newUser := callJSON(h, http.MethodPost, "/api/v1/users/", "10.0.0.3:1", `{"username":"bob","password":"password","role":"user"}`, session)
	if newUser.Code != 201 {
		t.Fatalf("create user = %d", newUser.Code)
	}
	create := callJSON(h, http.MethodPost, "/api/v1/users/2/api-tokens", "10.0.0.3:1", `{"name":"deploy","scopes":["repo:007:write"]}`, session)
	if create.Code != 201 || !strings.Contains(create.Body.String(), `"name":"deploy"`) {
		t.Fatalf("token = %d %s", create.Code, create.Body.String())
	}
	if w := callJSON(h, http.MethodGet, "/api/v1/users/2/api-tokens", "10.0.0.3:1", "", session); w.Code != 200 {
		t.Fatalf("list tokens = %d", w.Code)
	}
	if w := callJSON(h, http.MethodDelete, "/api/v1/users/2/api-tokens/1", "10.0.0.3:1", "", session); w.Code != 204 {
		t.Fatalf("revoke token = %d", w.Code)
	}
	if w := callJSON(h, http.MethodDelete, "/api/v1/users/2", "10.0.0.3:1", "", session); w.Code != 204 {
		t.Fatalf("delete user = %d", w.Code)
	}
	logout := callJSON(h, http.MethodPost, "/api/v1/auth/logout", "10.0.0.3:1", "", session)
	if logout.Code != 204 {
		t.Fatalf("logout = %d", logout.Code)
	}
	if callJSON(h, http.MethodPost, "/api/v1/auth/logout", "10.0.0.3:1", "", session).Code != 401 {
		t.Fatal("logged out session accepted")
	}
}

// TestTokenTTLAndRevokePathContract — рест-контракт /users/{id}/
// api-tokens (аудит 2026-08-30, сессия 45): ttl<0 → 400 (раньше молча
// создавался бессрочный: engine видит только ttl>0), ttl=0/отсутствие
// → 201 бессрочный; revoke сверяет {id} пути с владельцем токена —
// чужой id → 404, свой → 204.
func TestTokenTTLAndRevokePathContract(t *testing.T) {
	a, _ := handlerAuth(t)
	h := BuildAdminRouter(Deps{Auth: a, SetupToken: "setup"})
	admin, err := a.CreateUser(t.Context(), "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	other, err := a.CreateUser(t.Context(), "bob", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/users/" + strconv.FormatInt(admin.ID, 10) + "/api-tokens"

	if w := callJSON(h, http.MethodPost, path, "10.0.0.4:1", `{"name":"neg","ttl":-1}`, session); w.Code != http.StatusBadRequest {
		t.Fatalf("ttl=-1 = %d, хочу 400", w.Code)
	} else if !strings.Contains(w.Body.String(), "validation_error") {
		t.Errorf("тело ttl=-1 = %s, хочу validation_error", w.Body.String())
	}

	create := callJSON(h, http.MethodPost, path, "10.0.0.4:1", `{"name":"forever"}`, session)
	if create.Code != http.StatusCreated {
		t.Fatalf("ttl отсутствует = %d, хочу 201 (бессрочный)", create.Code)
	}
	if exp, _ := responseMap(t, create)["expires_at"].(string); exp != "0001-01-01T00:00:00Z" {
		t.Errorf("expires_at без ttl = %q, хочу нулевое время", exp)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	tokenID := strconv.FormatInt(created.ID, 10)

	foreign := "/api/v1/users/" + strconv.FormatInt(other.ID, 10) + "/api-tokens/" + tokenID
	if w := callJSON(h, http.MethodDelete, foreign, "10.0.0.4:1", "", session); w.Code != http.StatusNotFound {
		t.Fatalf("revoke с чужим {id} = %d, хочу 404", w.Code)
	}
	if w := callJSON(h, http.MethodDelete, path+"/"+tokenID, "10.0.0.4:1", "", session); w.Code != http.StatusNoContent {
		t.Fatalf("revoke со своим {id} = %d, хочу 204", w.Code)
	}
}

// TestSetupPasswordMinimumLength — /setup с пустым/коротким паролем
// даёт 400 validation_error (движок отвергает до БД), 8 байт — 201;
// слабую учётку в bootstrap-окне создать нельзя (внешнее ревью
// раунд 5).
func TestSetupPasswordMinimumLength(t *testing.T) {
	a, _ := handlerAuth(t)
	h := BuildAdminRouter(Deps{Auth: a})
	for _, tc := range []struct {
		password string
		code     int
	}{
		{"", 400},
		{"1234567", 400},
		{"12345678", 201},
	} {
		w := callJSON(h, http.MethodPost, "/api/v1/setup", "10.0.0.1:1", `{"username":"admin","password":"`+tc.password+`"}`, "")
		if w.Code != tc.code {
			t.Fatalf("setup с паролем длины %d = %d, хочу %d", len(tc.password), w.Code, tc.code)
		}
		if tc.code == 400 {
			m := responseMap(t, w)
			if m["error"] != "validation_error" {
				t.Fatalf("код ошибки = %v, хочу validation_error", m["error"])
			}
		}
	}
}

// TestSetupAtomicBootstrap — 20 параллельных POST /setup в
// bootstrap-окне: ровно один 201, остальные 403 setup_already_done,
// в таблице один пользователь (аудит 2026-08-27). RemoteAddr у каждой
// горутины свой — тестируем атомарность, а не rate limiter.
func TestSetupAtomicBootstrap(t *testing.T) {
	a, _ := handlerAuth(t)
	h := BuildAdminRouter(Deps{Auth: a})
	setup := `{"username":"admin","password":"password"}`

	const writers = 20
	codes := make(chan int, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/setup", strings.NewReader(setup))
			r.RemoteAddr = "10.1." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256+1) + ":1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			codes <- w.Code
		}(i)
	}
	wg.Wait()
	close(codes)
	created := 0
	for code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusForbidden:
		default:
			t.Fatalf("неожиданный статус /setup в гонке: %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("создано админов %d, хочу ровно 1", created)
	}
	all, err := a.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("в таблице %d пользователей, хочу 1", len(all))
	}
}

func usersByID(t *testing.T, a *auth.Service, id int64) []domain.User {
	t.Helper()
	u, err := a.User(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return []domain.User{u}
}

// TestAuthBodyLimit — JSON-тело сверх 1 MiB: 413 payload_too_large,
// а не OOM/400. Анонимные /setup и /auth/login — главные OOM-векторы
// аудита 2026-08-27, оба обязаны упираться в MaxBytesReader.
// TestLoginCatalogFailureNotUnauthorized — сбой каталога при логине —
// 503 unavailable, а не 401 invalid_credentials: 403/401 при сбое БД
// дезинформировал бы мониторинг и brute-force-детекторы
// (аудит 2026-08-27).
func TestLoginCatalogFailureNotUnauthorized(t *testing.T) {
	users := &failingUserStore{FakeUserStore: testutil.NewFakeUserStore(), err: errors.New("db down")}
	a, err := auth.New(auth.Config{Users: users, Tokens: &handlerTokens{}, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("33333333-3333-4333-8333-333333333333"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h := BuildAdminRouter(Deps{Auth: a})
	w := callJSON(h, http.MethodPost, "/api/v1/auth/login", "10.0.0.1:1", `{"username":"x","password":"y"}`, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("логин при сбое каталога = %d (%s), хочу 503", w.Code, w.Body.String())
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error != "unavailable" {
		t.Fatalf("код ошибки = %q (%v), хочу unavailable", e.Error, err)
	}
}

// failingUserStore подменяет только чтение пользователя по имени:
// остальное — поведение фейка.
type failingUserStore struct {
	*testutil.FakeUserStore
	err error
}

func (s *failingUserStore) UserByUsername(ctx context.Context, username string) (domain.User, error) {
	if s.err != nil {
		return domain.User{}, s.err
	}
	return s.FakeUserStore.UserByUsername(ctx, username)
}

// failingRevocations деградирует только вставку отзыва: остальное —
// поведение фейка.
type failingRevocations struct {
	*testutil.FakeRevocations
	err error
}

func (f *failingRevocations) InsertRevocation(ctx context.Context, jti string, now, expiresAt time.Time) error {
	if f.err != nil {
		return f.err
	}
	return f.FakeRevocations.InsertRevocation(ctx, jti, now, expiresAt)
}

// TestLogoutDBFailureUnavailable — сбой БД при вставке отзыва: logout —
// 503 unavailable (та же 503-политика, что у остальных auth-путей,
// сессии 25 и 30), не сырой 500. In-process отзыв при этом применён
// (rememberRevoked до return): повторный запрос с тем же JWT на ЭТОМ
// инстансе уже 401. Контроль: исправный каталог — 204.
func TestLogoutDBFailureUnavailable(t *testing.T) {
	revocations := &failingRevocations{FakeRevocations: testutil.NewFakeRevocations()}
	// Два UUID: у каждой IssueSession свой jti — контрольная сессия не
	// наследует отзыв первой (FixedRand раздаёт список по кругу).
	a, err := auth.New(auth.Config{Users: testutil.NewFakeUserStore(), Tokens: &handlerTokens{}, Revocations: revocations, Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h := BuildAdminRouter(Deps{Auth: a})
	if w := callJSON(h, http.MethodPost, "/api/v1/setup", "10.0.0.1:1", `{"username":"admin","password":"password"}`, ""); w.Code != 201 {
		t.Fatalf("setup = %d %s", w.Code, w.Body.String())
	}
	login := callJSON(h, http.MethodPost, "/api/v1/auth/login", "10.0.0.1:1", `{"username":"admin","password":"password"}`, "")
	if login.Code != 200 {
		t.Fatalf("login = %d %s", login.Code, login.Body.String())
	}
	session := responseMap(t, login)["token"].(string)

	revocations.err = errors.New("db down")
	logout := callJSON(h, http.MethodPost, "/api/v1/auth/logout", "10.0.0.1:2", "", session)
	if logout.Code != http.StatusServiceUnavailable {
		t.Fatalf("logout при сбое БД = %d (%s), хочу 503", logout.Code, logout.Body.String())
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(logout.Body.Bytes(), &e); err != nil || e.Error != "unavailable" {
		t.Fatalf("код ошибки = %q (%v), хочу unavailable", e.Error, err)
	}
	// In-process отзыв пережил ошибку записи.
	if callJSON(h, http.MethodPost, "/api/v1/auth/logout", "10.0.0.1:2", "", session).Code != 401 {
		t.Fatal("сессия после сбойного logout осталась валидной")
	}

	// Контроль: исправная вставка — 204.
	revocations.err = nil
	relogin := callJSON(h, http.MethodPost, "/api/v1/auth/login", "10.0.0.1:3", `{"username":"admin","password":"password"}`, "")
	if relogin.Code != 200 {
		t.Fatalf("повторный login = %d %s", relogin.Code, relogin.Body.String())
	}
	fresh := responseMap(t, relogin)["token"].(string)
	if w := callJSON(h, http.MethodPost, "/api/v1/auth/logout", "10.0.0.1:3", "", fresh); w.Code != 204 {
		t.Fatalf("logout при исправном каталоге = %d (%s), хочу 204", w.Code, w.Body.String())
	}
}

func TestAuthBodyLimit(t *testing.T) {
	huge := `{"username":"` + strings.Repeat("a", 2<<20) + `"}`
	a, users := handlerAuth(t)
	h := BuildAdminRouter(Deps{Auth: a})
	for _, path := range []string{"/api/v1/setup", "/api/v1/auth/login"} {
		w := callJSON(h, http.MethodPost, path, "10.0.0.1:1", huge, "")
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s c телом 2MiB = %d, хочу 413 (тело %s)", path, w.Code, w.Body.String())
		}
		var e struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error != "payload_too_large" {
			t.Fatalf("%s: код ошибки = %q (%v), хочу payload_too_large", path, e.Error, err)
		}
	}
	// Лимит не создал пользователей и не жрёт тело дальше.
	if has, _ := a.HasUsers(context.Background()); has {
		t.Error("oversized /setup создал пользователя")
	}
	if _, err := users.UserByUsername(context.Background(), "a"); err == nil {
		t.Error("oversized /auth/login что-то записал")
	}
}
