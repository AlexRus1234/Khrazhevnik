package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

type tokenFake struct {
	next      int64
	values    map[int64]domain.APIToken
	createErr error
	byHashErr error
	touchErr  error
	revokeErr error
	lastTouch time.Time
}

func (f *tokenFake) CreateToken(_ context.Context, t domain.APIToken) (domain.APIToken, error) {
	if f.createErr != nil {
		return domain.APIToken{}, f.createErr
	}
	f.next++
	t.ID = f.next
	f.values[t.ID] = t
	return t, nil
}
func (f *tokenFake) TokenBySHA256(_ context.Context, h string) (domain.APIToken, error) {
	if f.byHashErr != nil {
		return domain.APIToken{}, f.byHashErr
	}
	for _, t := range f.values {
		if t.SHA256 == h {
			return t, nil
		}
	}
	return domain.APIToken{}, &domain.NotFoundError{}
}
func (f *tokenFake) TokensByUser(_ context.Context, id int64) ([]domain.APIToken, error) {
	var out []domain.APIToken
	for _, t := range f.values {
		if t.UserID == id {
			out = append(out, t)
		}
	}
	return out, nil
}
func (f *tokenFake) DeleteToken(context.Context, int64) error { return nil }
func (f *tokenFake) RevokeToken(_ context.Context, id int64, at time.Time) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	t := f.values[id]
	t.RevokedAt = at
	f.values[id] = t
	return nil
}
func (f *tokenFake) TouchToken(_ context.Context, _ int64, at time.Time) error {
	f.lastTouch = at
	return f.touchErr
}

type errorUserStore struct {
	*testutil.FakeUserStore
	hasErr, usersErr, userErr, byNameErr, deleteErr, updateErr error
}

func (s *errorUserStore) HasUsers(context.Context) (bool, error) {
	if s.hasErr != nil {
		return false, s.hasErr
	}
	return s.FakeUserStore.HasUsers(context.Background())
}
func (s *errorUserStore) UserByUsername(ctx context.Context, username string) (domain.User, error) {
	if s.byNameErr != nil {
		return domain.User{}, s.byNameErr
	}
	return s.FakeUserStore.UserByUsername(ctx, username)
}
func (s *errorUserStore) Users(context.Context) ([]domain.User, error) {
	if s.usersErr != nil {
		return nil, s.usersErr
	}
	return s.FakeUserStore.Users(context.Background())
}
func (s *errorUserStore) User(ctx context.Context, id int64) (domain.User, error) {
	if s.userErr != nil {
		return domain.User{}, s.userErr
	}
	return s.FakeUserStore.User(ctx, id)
}
func (s *errorUserStore) DeleteUser(ctx context.Context, id int64) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.FakeUserStore.DeleteUser(ctx, id)
}
func (s *errorUserStore) UpdateUser(ctx context.Context, u domain.User) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	return s.FakeUserStore.UpdateUser(ctx, u)
}

type movingClock struct{ now time.Time }

func (c *movingClock) Now() time.Time { return c.now }

var _ port.Clock = (*movingClock)(nil)

func newTestAuth(t *testing.T) (*Service, *tokenFake) {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tf := &tokenFake{values: map[int64]domain.APIToken{}}
	a, err := New(Config{Users: users, Tokens: tf, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateUser(context.Background(), "alice", "correct", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	return a, tf
}

func TestPasswordGuardAndSessionVersion(t *testing.T) {
	a, _ := newTestAuth(t)
	if _, err := a.CreateUser(context.Background(), "long", string(make([]byte, 73)), domain.RoleUser); err == nil {
		t.Fatal("73-byte password accepted")
	}
	u, err := a.VerifyPassword(context.Background(), "alice", "correct")
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.IssueSession(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err := a.InvalidateUserSessions(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession(context.Background(), token); err == nil {
		t.Fatal("old session remained valid")
	}
}

func TestAPITokenSecretNotStored(t *testing.T) {
	a, tf := newTestAuth(t)
	u, _ := a.User(context.Background(), 1)
	tkn, raw, err := a.IssueAPIToken(context.Background(), u, "test", []domain.Scope{"repo:007:write"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tkn.SHA256 == raw || tkn.Prefix == "" {
		t.Fatal("token secret leaked in model")
	}
	if _, got, err := a.VerifyAPIToken(context.Background(), raw); err != nil || got.ID != u.ID {
		t.Fatalf("verify: %v", err)
	}
	if err := tf.RevokeToken(context.Background(), tkn.ID, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.VerifyAPIToken(context.Background(), raw); err == nil {
		t.Fatal("revoked token accepted")
	}
}

func TestAuthDelegatesAndDeleteBranches(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	if got, err := users.HasUsers(ctx); err != nil || got {
		t.Fatal("new fake should be empty")
	}
	u, err := users.CreateUser(ctx, domain.User{Username: "a", TokenVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(Config{Users: users, Tokens: &tokenFake{values: map[int64]domain.APIToken{}}, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(1, 0)), Rand: testutil.FixedRand(), JWTSecret: "x", SessionTTL: time.Hour})
	if ok, _ := s.HasUsers(ctx); !ok {
		t.Fatal("HasUsers")
	}
	if us, err := s.Users(ctx); err != nil || len(us) != 1 {
		t.Fatalf("Users: %v", err)
	}
	if got, err := s.User(ctx, u.ID); err != nil || got.ID != u.ID {
		t.Fatalf("User: %v", err)
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, u.ID); err == nil {
		t.Fatal("missing delete error")
	}
	bad := &errorUserStore{FakeUserStore: testutil.NewFakeUserStore(), userErr: errors.New("user")}
	bad.FakeUserStore.CreateUser(ctx, domain.User{Username: "b", TokenVersion: 1})
	s.cfg.Users = bad
	if err := s.DeleteUser(ctx, 1); err == nil {
		t.Fatal("delete lookup error")
	}
	bad.userErr = nil
	bad.deleteErr = errors.New("delete")
	if err := s.DeleteUser(ctx, 1); err == nil {
		t.Fatal("delete failure")
	}
	bad.deleteErr = nil
	bad.updateErr = errors.New("update")
	if err := s.InvalidateUserSessions(ctx, 1); err == nil {
		t.Fatal("update failure")
	}
	if _, err := s.Tokens(ctx, 1); err != nil {
		t.Fatal(err)
	}
	tf := s.cfg.Tokens.(*tokenFake)
	tf.revokeErr = errors.New("revoke")
	if err := s.RevokeToken(ctx, 1); err == nil {
		t.Fatal("revoke failure lost")
	}
}

func TestLoginAndIssueFailures(t *testing.T) {
	a, _ := newTestAuth(t)
	if _, err := a.Login(context.Background(), "alice", "wrong"); err == nil {
		t.Fatal("bad login accepted")
	}
	if token, err := a.Login(context.Background(), "alice", "correct"); err != nil || token == "" {
		t.Fatalf("login: %v", err)
	}
	if _, err := a.IssueSession(context.Background(), domain.User{}); err != nil {
		t.Fatal(err)
	}
	bad := &errorUserStore{FakeUserStore: testutil.NewFakeUserStore(), hasErr: errors.New("has"), usersErr: errors.New("users")}
	bad.FakeUserStore.CreateUser(context.Background(), domain.User{Username: "x", TokenVersion: 1})
	a.cfg.Users = bad
	if _, err := a.HasUsers(context.Background()); err == nil {
		t.Fatal("HasUsers error lost")
	}
	if _, err := a.Users(context.Background()); err == nil {
		t.Fatal("Users error lost")
	}
	bad.userErr = errors.New("user")
	if _, err := a.User(context.Background(), 1); err == nil {
		t.Fatal("User error lost")
	}
	if _, err := a.CreateUser(context.Background(), "bad name", "password", domain.RoleUser); err == nil {
		t.Fatal("invalid username accepted")
	}
	a.cfg.Rand = testutil.FailingRand(errors.New("rand"))
	if _, err := a.IssueSession(context.Background(), domain.User{}); err == nil {
		t.Fatal("session rand failure lost")
	}
	a2, _ := newTestAuth(t)
	a2.cfg.Rand = testutil.FailingRand(errors.New("rand"))
	if _, err := a2.Login(context.Background(), "alice", "correct"); err == nil {
		t.Fatal("login issue failure lost")
	}
}

// Стоимость bcrypt — из конфига: cost=4 — логин работает, cost=99 —
// конфиг невалиден (движок не доверяет конфигу и сам проверяет
// диапазон).
func TestBcryptCostConfig(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	tf := &tokenFake{values: map[int64]domain.APIToken{}}
	cfg := Config{Users: users, Tokens: tf, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.BcryptCost = 4
	if _, err := a.CreateUser(ctx, "alice", "correct", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, "alice", "correct"); err != nil {
		t.Fatalf("логин при cost=4: %v", err)
	}
	bad := cfg
	bad.BcryptCost = 99
	if _, err := New(bad); err == nil {
		t.Fatal("cost=99 принят")
	}
}

// Пароль длиннее 72 байт: сравнение идёт по bcrypt-обрезке, затем
// явное отклонение — короткое замыкание по длине (тайминг-оракул
// длины) убрано (аудит 2026-08-27).
func TestLongPasswordRejectedAfterCompare(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestAuth(t)
	if _, err := a.CreateUser(ctx, "trunc", strings.Repeat("x", 72), domain.RoleUser); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyPassword(ctx, "trunc", strings.Repeat("x", 80)); !errors.Is(err, &domain.TooLargeError{}) {
		t.Fatalf("длинный пароль с верной 72-байтной обрезкой: %v, хочу TooLargeError", err)
	}
	if _, err := a.VerifyPassword(ctx, "trunc", strings.Repeat("y", 80)); !errors.Is(err, &domain.ForbiddenError{}) {
		t.Fatalf("длинный неверный пароль: %v, хочу ForbiddenError", err)
	}
}

// Тайминг-паритет: путь несуществующего пользователя (dummy-хэш) стоит
// как путь реального. Порог мягкий (CI-шум), прогон пропускается в
// -short (аудит 2026-08-27).
func TestDummyHashTimingParity(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-тест — не для -short")
	}
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	a, err := New(Config{Users: users, Tokens: &tokenFake{values: map[int64]domain.APIToken{}}, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour, BcryptCost: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateUser(ctx, "alice", "correct", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	// прогрев sync.Once dummy-хэша: сам тест меряет только сравнения
	if _, err := a.VerifyPassword(ctx, "ghost", "x"); err == nil {
		t.Fatal("несуществующий пользователь принят")
	}
	bench := func(username string) time.Duration {
		best := time.Duration(1 << 62)
		for range 7 {
			start := time.Now()
			if _, err := a.VerifyPassword(ctx, username, "wrong-password"); err == nil {
				t.Fatalf("%s прошёл без ошибки", username)
			}
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	dummy, real := bench("ghost"), bench("alice")
	if dummy < real/2 {
		t.Fatalf("тайминг-оракул: путь dummy %v вдвое дешевле пути real %v", dummy, real)
	}
}

// Троттлинг last_used: в пределах touch_interval запись не повторяется,
// за границей интервала — пишется снова.
func TestTouchIntervalThrottle(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	tf := &tokenFake{values: map[int64]domain.APIToken{}}
	a, err := New(Config{Users: users, Tokens: tf, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour, TouchInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateUser(ctx, "alice", "correct", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	u, _ := a.User(ctx, 1)
	// токен бессрочный: сдвиг часов в тесте не должен истекать его
	_, raw, err := a.IssueAPIToken(ctx, u, "ci", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.VerifyAPIToken(ctx, raw); err != nil {
		t.Fatal(err)
	}
	first := tf.lastTouch
	if _, _, err := a.VerifyAPIToken(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if !tf.lastTouch.Equal(first) {
		t.Fatal("touch не затроттлен в интервале")
	}
	a.cfg.Clock = testutil.FixedClock(time.Unix(100, 0).Add(2 * time.Hour))
	if _, _, err := a.VerifyAPIToken(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if tf.lastTouch.Equal(first) {
		t.Fatal("touch не записан после интервала")
	}
}

// failingRevocations — сбой персистентного слоя отзывов поверх фейка.
type failingRevocations struct {
	*testutil.FakeRevocations
	err error
}

func (f *failingRevocations) IsRevoked(ctx context.Context, jti string, now time.Time) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.FakeRevocations.IsRevoked(ctx, jti, now)
}

func (f *failingRevocations) InsertRevocation(ctx context.Context, jti string, now, expiresAt time.Time) error {
	if f.err != nil {
		return f.err
	}
	return f.FakeRevocations.InsertRevocation(ctx, jti, now, expiresAt)
}

// Персистентный отзыв (сессия 25): logout переживает «рестарт» — новый
// Service с чистой in-memory картой на том же каталоге отклоняет
// отозванный токен и принимает живой.
func TestRevocationPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	tf := &tokenFake{values: map[int64]domain.APIToken{}}
	revocations := testutil.NewFakeRevocations()
	build := func(rand port.Rand) *Service {
		a, err := New(Config{Users: users, Tokens: tf, Revocations: revocations, Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: rand, JWTSecret: "secret", SessionTTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a1 := build(testutil.FixedRand("11111111-1111-4111-8111-111111111111"))
	admin, err := a1.CreateUser(ctx, "alice", "correct", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	token, err := a1.IssueSession(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := a1.RevokeSession(ctx, "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}

	// «Рестарт»: новый Service, память пуста, каталог тот же.
	a2 := build(testutil.FixedRand("22222222-2222-4222-8222-222222222222"))
	if _, err := a2.ValidateSession(ctx, token); !errors.Is(err, &domain.ForbiddenError{}) {
		t.Fatalf("отозванная сессия пережила рестарт: %v", err)
	}
	live, err := a2.IssueSession(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a2.ValidateSession(ctx, live); err != nil {
		t.Fatalf("живая сессия после рестарта: %v", err)
	}
	// Сбой каталога при проверке отзыва — Unavailable, не Forbidden.
	a2.cfg.Revocations = &failingRevocations{FakeRevocations: revocations, err: errors.New("db down")}
	if _, err := a2.ValidateSession(ctx, live); !errors.Is(err, &domain.UnavailableError{}) {
		t.Fatalf("сбой проверки отзыва: %v, хочу UnavailableError", err)
	}

	// Ошибка вставки отзыва — Unavailable (logout не должен врать 204
	// и не должен отвечать сырым 500: сессия 30), но сессия гасится
	// в процессе.
	a3 := build(testutil.FixedRand("33333333-3333-4333-8333-333333333333"))
	tok3, err := a3.IssueSession(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	a3.cfg.Revocations = &failingRevocations{err: errors.New("db down")}
	if err := a3.RevokeSession(ctx, "33333333-3333-4333-8333-333333333333"); !errors.Is(err, &domain.UnavailableError{}) {
		t.Fatalf("ошибка персистентного отзыва: %v, хочу UnavailableError", err)
	}
	if _, err := a3.ValidateSession(ctx, tok3); !errors.Is(err, &domain.ForbiddenError{}) {
		t.Fatalf("сессия не отозвана в процессе после сбоя вставки: %v", err)
	}
}

// In-memory fast-path ограничен и чистится по exp: потолок держится,
// свежий отзыв вытесняет старейший, а персистентный слой помнит всё.
func TestRevokedMemoryBounded(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestAuth(t)
	if err := a.RevokeSession(ctx, "jti-db-persisted"); err != nil {
		t.Fatal(err)
	}
	until := time.Unix(100, 0).Add(time.Hour)
	for i := 0; i < maxRevokedMemory; i++ {
		a.revoked[fmt.Sprintf("jti-%d", i)] = until
	}
	a.revoked["jti-expired"] = time.Unix(50, 0)
	a.rememberRevoked("jti-new", until.Add(time.Minute))
	if len(a.revoked) > maxRevokedMemory {
		t.Fatalf("карта отзывов %d записей, потолок %d", len(a.revoked), maxRevokedMemory)
	}
	if !a.revokedInMemory("jti-new") {
		t.Fatal("свежий отзыв вытеснен")
	}
	if a.revokedInMemory("jti-expired") {
		t.Fatal("просроченная запись не вычищена")
	}
	// Вытеснение произвольно (map-порядок), поэтому конкретную запись
	// в памяти не проверяем: персистентный слой помнит всё в любом случае.
	yes, err := a.cfg.Revocations.IsRevoked(ctx, "jti-db-persisted", time.Unix(100, 0))
	if err != nil || !yes {
		t.Fatalf("каталог потерял вытесненный из памяти отзыв: %v, %v", yes, err)
	}
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("incomplete auth config accepted")
	}
}

// ctxAwareAuditLog — фейк, отказавший в записи при мёртвом ctx:
// имитация честного store (до фикса Login писал в request-ctx —
// обрыв соединения терял auth.login).
type ctxAwareAuditLog struct {
	testutil.FakeAuditLog
}

func (l *ctxAwareAuditLog) Record(ctx context.Context, e domain.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return l.FakeAuditLog.Record(ctx, e)
}

// Обрыв соединения на POST /auth/login до Record (request-ctx мёртв)
// не должен терять запись auth.login — Login пишет аудит через
// WithoutCancel + свой таймаут (по образцу web-аудита, сессия 37).
func TestLoginAuditSurvivesCancelledContext(t *testing.T) {
	log := &ctxAwareAuditLog{}
	a, err := New(Config{Users: testutil.NewFakeUserStore(), Tokens: &tokenFake{values: map[int64]domain.APIToken{}}, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour, Audit: log})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateUser(context.Background(), "alice", "correct", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Login(ctx, "alice", "correct"); err != nil {
		t.Fatalf("логин с оборванным соединением: %v", err)
	}
	entries, _ := log.AuditEntries(context.Background(), 0, 10)
	found := 0
	for _, e := range entries {
		if e.Action == "auth.login" {
			found++
			if e.Result != domain.AuditOK {
				t.Errorf("auth.login result = %q, хочу ok", e.Result)
			}
		}
	}
	if found != 1 {
		t.Fatalf("записей auth.login = %d, хочу 1 — обрыв соединения потерял запись", found)
	}
}

// Транзиентный сбой каталога на пути аутентификации — UnavailableError
// (web мапит в 503), отсутствие записи — по-прежнему Forbidden.
// Проглатывание ошибки БД превращало любой сбой в «неверные учётные
// данные» (аудит 2026-08-27).
func TestStoreFailuresSurfaceAsUnavailable(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewFakeUserStore()
	tf := &tokenFake{values: map[int64]domain.APIToken{}}
	a, err := New(Config{Users: users, Tokens: tf, Revocations: testutil.NewFakeRevocations(), Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.CreateUser(ctx, "alice", "correct", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.IssueSession(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := a.IssueAPIToken(ctx, admin, "ci", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	bad := &errorUserStore{FakeUserStore: users, byNameErr: errors.New("db down")}
	a.cfg.Users = bad
	_, err = a.VerifyPassword(ctx, "alice", "correct")
	if !errors.Is(err, &domain.UnavailableError{}) {
		t.Fatalf("транзиентный сбой: %v, хочу UnavailableError", err)
	}
	if errors.Is(err, &domain.ForbiddenError{}) {
		t.Fatal("сбой каталога маскируется под неверные учётные данные")
	}
	// Отсутствующий пользователь (NotFound из store, не сбой) — Forbidden.
	bad.byNameErr = &domain.NotFoundError{What: "пользователь", Key: "ghost"}
	if _, err := a.VerifyPassword(ctx, "ghost", "x"); !errors.Is(err, &domain.ForbiddenError{}) {
		t.Fatalf("несуществующий пользователь: %v, хочу ForbiddenError", err)
	}
	bad.byNameErr = nil
	bad.userErr = errors.New("db down")
	if _, err := a.ValidateSession(ctx, session); !errors.Is(err, &domain.UnavailableError{}) {
		t.Fatalf("ValidateSession при сбое каталога: %v, хочу UnavailableError", err)
	}
	_, _, err = a.VerifyAPIToken(ctx, raw)
	if !errors.Is(err, &domain.UnavailableError{}) {
		t.Fatalf("VerifyAPIToken при сбое каталога: %v, хочу UnavailableError", err)
	}
	bad.userErr = nil
	tf.byHashErr = errors.New("db down")
	if _, _, err := a.VerifyAPIToken(ctx, raw); !errors.Is(err, &domain.UnavailableError{}) {
		t.Fatalf("VerifyAPIToken при сбое поиска токена: %v, хочу UnavailableError", err)
	}
	tf.byHashErr = nil
	if _, _, err := a.VerifyAPIToken(ctx, raw); err != nil {
		t.Fatalf("после устранения сбоя токен должен пройти: %v", err)
	}
}

func TestSessionValidationClaimsAlgorithmRevocationAndExpiry(t *testing.T) {
	a, _ := newTestAuth(t)
	u, _ := a.User(context.Background(), 1)
	_, _ = a.IssueSession(context.Background(), u)
	_ = a.RevokeSession(context.Background(), "")
	if err := a.RevokeSession(context.Background(), "jti"); err != nil {
		t.Fatal(err)
	}
	revokedClaims := jwt.MapClaims{"sub": "1", "jti": "jti", "ver": float64(u.TokenVersion), "exp": float64(time.Unix(100, 0).Add(time.Hour).Unix())}
	revokedRaw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, revokedClaims).SignedString([]byte("secret"))
	if _, err := a.ValidateSession(context.Background(), revokedRaw); err == nil {
		t.Fatal("revoked session accepted")
	}
	if _, err := a.ValidateSession(context.Background(), "not.jwt"); err == nil {
		t.Fatal("malformed JWT")
	}
	badAlg := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"sub": "1", "ver": float64(1)})
	algRaw, _ := badAlg.SignedString([]byte("secret"))
	if _, err := a.ValidateSession(context.Background(), algRaw); err == nil {
		t.Fatal("HS512 accepted")
	}
	for _, claims := range []jwt.MapClaims{{"sub": 1, "ver": float64(1)}, {"sub": "bad", "ver": float64(1)}, {"sub": "1"}, {"sub": "1", "ver": float64(9)}} {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := tok.SignedString([]byte("secret"))
		if _, err := a.ValidateSession(context.Background(), signed); err == nil {
			t.Fatalf("invalid claims accepted: %v", claims)
		}
	}
	// A different JTI remains valid while the revoked one is rejected.
	liveClaims := jwt.MapClaims{"sub": "1", "jti": "live", "ver": float64(u.TokenVersion), "exp": float64(time.Unix(100, 0).Add(time.Hour).Unix())}
	live, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, liveClaims).SignedString([]byte("secret"))
	if _, err := a.ValidateSession(context.Background(), live); err != nil {
		t.Fatalf("unrelated session rejected: %v", err)
	}
	// A revoked entry is removed after its retention period and no longer blocks a matching JTI.
	clock := &movingClock{now: time.Unix(100, 0)}
	a.cfg.Clock = clock
	claims := jwt.MapClaims{"sub": fmt.Sprint(u.ID), "jti": "gone", "ver": float64(u.TokenVersion), "exp": float64(clock.now.Add(5 * time.Hour).Unix())}
	valid, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err := a.RevokeSession(context.Background(), "gone"); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(4 * time.Hour)
	if _, err := a.ValidateSession(context.Background(), valid); err != nil {
		t.Fatalf("expired revocation not cleaned: %v", err)
	}
	clock.now = clock.now.Add(2 * time.Hour)
	if _, err := a.ValidateSession(context.Background(), valid); err == nil {
		t.Fatal("expired JWT accepted")
	}
}

func TestAPITokenExpiryInvalidTouchAndScopeErrors(t *testing.T) {
	a, tf := newTestAuth(t)
	u, _ := a.User(context.Background(), 1)
	if _, _, err := a.IssueAPIToken(context.Background(), u, "named", []domain.Scope{"bad"}, 0); err == nil {
		t.Fatal("bad scope accepted")
	}
	tf.createErr = errors.New("create")
	if _, _, err := a.IssueAPIToken(context.Background(), u, "named", nil, 0); err == nil {
		t.Fatal("create failure lost")
	}
	tf.createErr = nil
	token, raw, err := a.IssueAPIToken(context.Background(), u, "named", nil, time.Hour)
	if err != nil || token.Name != "named" {
		t.Fatalf("name: %v", err)
	}
	if _, _, err := a.VerifyAPIToken(context.Background(), "khz_bad"); err == nil {
		t.Fatal("bad format accepted")
	}
	if _, _, err := a.VerifyAPIToken(context.Background(), raw+"x"); err == nil {
		t.Fatal("bad token accepted")
	}
	tf.touchErr = errors.New("touch")
	hooked := 0
	a.cfg.ErrorHook = func(error) { hooked++ }
	if _, _, err := a.VerifyAPIToken(context.Background(), raw); err != nil {
		t.Fatalf("сбой косметической записи last_used не должен валить токен: %v", err)
	}
	if hooked == 0 {
		t.Fatal("сбой touch проглочен молча (нет ErrorHook)")
	}
	tf.touchErr = nil
	if err := tf.RevokeToken(context.Background(), token.ID, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.VerifyAPIToken(context.Background(), raw); err == nil {
		t.Fatal("revoked accepted")
	}
	// Expiry is checked at the current clock boundary.
	token.RevokedAt = time.Time{}
	token.ExpiresAt = time.Unix(100, 0)
	tf.values[token.ID] = token
	a.cfg.Clock = testutil.FixedClock(time.Unix(100, 0))
	if _, _, err := a.VerifyAPIToken(context.Background(), raw); err == nil {
		t.Fatal("expired accepted")
	}
}
