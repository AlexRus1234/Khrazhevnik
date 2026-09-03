// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package auth contains authentication use cases. It deliberately has no
// HTTP knowledge: transport policy belongs to core/web.
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

const maxBcryptPassword = 72

// Границы стоимости bcrypt (параллельны валидации конфига): ниже 4
// перебор слишком дешёв, выше 15 — логин на минуты.
const (
	minBcryptCost = 4
	maxBcryptCost = 15
)

// dummyPassword — фиксированная строка для dummy-хэша пути
// несуществующего пользователя; заведомо короче 72 байт.
const dummyPassword = "khrazhevnik-dummy-password"

// maxRevokedMemory — потолок in-memory fast-path отзывов: сессии
// короткоживущие (SessionTTL), персистентный слой — источник истины,
// карта не должна расти безгранично (аудит 2026-08-27: чистилась
// только лениво и не имела потолка).
const maxRevokedMemory = 10000

// maxTouchMemory — потолок карты «токен → последнее touch»: токены
// удаляются, а ключи оставались бы навсегда; переполнение — полный
// сброс (потеря троттлинга до следующего touch — не уязвимость).
const maxTouchMemory = 10000

// loginAuditTimeout — потолок записи auth.login: WithoutCancel не
// наследует ни отмену соединения, ни дедлайны запроса, поэтому свой
// короткий предел (по образцу web/audit.go; вынести константу в общее
// место нельзя — domain без time).
const loginAuditTimeout = 5 * time.Second

// Config wires authentication to persistence and deterministic system ports.
type Config struct {
	Users  port.UserStore
	Tokens port.TokenStore
	// Revocations — персистентный отзыв JWT-сессий: logout переживает
	// рестарт процесса (аудит 2026-08-27); nil недопустим.
	Revocations port.SessionRevocationStore
	Audit       port.AuditLog
	Clock       port.Clock
	Rand        port.Rand
	JWTSecret   string
	SessionTTL  time.Duration
	// BcryptCost — стоимость хеширования паролей (4–15); 0 —
	// bcrypt.DefaultCost (прямой вызов без конфига).
	BcryptCost int
	// TouchInterval — минимальный интервал записи last_used API-токена;
	// 0 — писать на каждый запрос.
	TouchInterval time.Duration
	// ErrorHook — репортёр проглоченных ошибок (touch last_used):
	// ошибка возвращаться некому, молчать нельзя.
	ErrorHook func(error)
}

// Service is the authentication application service.
type Service struct {
	cfg       Config
	revokedMu sync.Mutex
	revoked   map[string]time.Time
	touchMu   sync.Mutex
	lastTouch map[int64]time.Time
	// dummyOnce/dummyHash — ленивый валидный bcrypt-хэш фиксированной
	// строки с той же стоимостью, что боевые хэши (тайминг-паритет
	// пути несуществующего пользователя).
	dummyOnce sync.Once
	dummyHash []byte
}

// New creates an authentication service.
func New(cfg Config) (*Service, error) {
	if cfg.Users == nil || cfg.Tokens == nil || cfg.Revocations == nil || cfg.Clock == nil || cfg.Rand == nil || cfg.JWTSecret == "" || cfg.SessionTTL <= 0 {
		return nil, errors.New("auth: неполная конфигурация")
	}
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcrypt.DefaultCost
	}
	if cfg.BcryptCost < minBcryptCost || cfg.BcryptCost > maxBcryptCost {
		return nil, fmt.Errorf("auth: bcrypt cost %d вне диапазона %d–%d", cfg.BcryptCost, minBcryptCost, maxBcryptCost)
	}
	return &Service{cfg: cfg, revoked: make(map[string]time.Time), lastTouch: make(map[int64]time.Time)}, nil
}

// Session is the trusted result of JWT validation, with role loaded from DB.
type Session struct {
	User domain.User
	JTI  string
}

// HasUsers reports whether bootstrap is still available.
func (s *Service) HasUsers(ctx context.Context) (bool, error) { return s.cfg.Users.HasUsers(ctx) }

// Users lists accounts for the administrative API.
func (s *Service) Users(ctx context.Context) ([]domain.User, error) { return s.cfg.Users.Users(ctx) }

// User loads an account.
func (s *Service) User(ctx context.Context, id int64) (domain.User, error) {
	return s.cfg.Users.User(ctx, id)
}

// DeleteUser removes an account after invalidating its sessions.
func (s *Service) DeleteUser(ctx context.Context, id int64) error {
	if err := s.InvalidateUserSessions(ctx, id); err != nil {
		return err
	}
	u, err := s.cfg.Users.User(ctx, id)
	if err != nil {
		return err
	}
	err = s.cfg.Users.DeleteUser(ctx, id)
	if err == nil {
		s.audit(ctx, u.Username, "user.delete", fmt.Sprintf("user:%d", id), domain.AuditOK, "")
	}
	return err
}

// Tokens lists a user's API tokens.
func (s *Service) Tokens(ctx context.Context, id int64) ([]domain.APIToken, error) {
	return s.cfg.Tokens.TokensByUser(ctx, id)
}

// RevokeToken revokes an API token.
func (s *Service) RevokeToken(ctx context.Context, id int64) error {
	return s.cfg.Tokens.RevokeToken(ctx, id, s.cfg.Clock.Now())
}

// CreateUser hashes password before persisting an account.
func (s *Service) CreateUser(ctx context.Context, username, password string, role domain.Role) (domain.User, error) {
	if err := domain.ValidateUsername(username); err != nil {
		return domain.User{}, err
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return domain.User{}, err
	}
	u, err := s.cfg.Users.CreateUser(ctx, domain.User{Username: username, PasswordHash: string(hash), Role: role, TokenVersion: 1, CreatedAt: s.cfg.Clock.Now()})
	if err == nil {
		s.audit(ctx, username, "user.create", "user:"+username, domain.AuditOK, "")
	}
	return u, err
}

// EnsureFirstAdmin atomically creates the first admin: a single
// INSERT ... WHERE NOT EXISTS in the store settles the bootstrap race
// (audit 2026-08-27: separate HasUsers+CreateUser let two parallel
// /setup calls create two admins). created=false — someone else won.
func (s *Service) EnsureFirstAdmin(ctx context.Context, username, password string) (domain.User, bool, error) {
	if err := domain.ValidateUsername(username); err != nil {
		return domain.User{}, false, err
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return domain.User{}, false, err
	}
	u, created, err := s.cfg.Users.EnsureFirstUser(ctx, domain.User{
		Username: username, PasswordHash: string(hash),
		Role: domain.RoleAdmin, TokenVersion: 1, CreatedAt: s.cfg.Clock.Now(),
	})
	if err == nil && created {
		s.audit(ctx, username, "setup", "user:"+username, domain.AuditOK, "")
	}
	return u, created, err
}

// hashPassword validates the bcrypt size limit and hashes the value
// with the configured cost.
func (s *Service) hashPassword(password string) ([]byte, error) {
	if len([]byte(password)) > maxBcryptPassword {
		return nil, &domain.TooLargeError{Size: int64(len([]byte(password))), Limit: maxBcryptPassword}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		// bcrypt has a hard 72-byte limit; never create an account after a hash failure.
		return nil, &domain.TooLargeError{Size: int64(len([]byte(password))), Limit: maxBcryptPassword}
	}
	return hash, nil
}

// dummyHashBytes генерирует при первом использовании валидный
// bcrypt-хэш фиксированной строки с той же стоимостью, что боевые
// хэши: путь несуществующего пользователя совпадает по времени с
// путём реального (тайминг-паритет). Хардкод константы ненадёжен —
// валидность строки ничем не проверялась (аудит 2026-08-27). nil —
// только если Generate невозможен (для фиксированной строки — никогда).
func (s *Service) dummyHashBytes() []byte {
	s.dummyOnce.Do(func() {
		if h, err := bcrypt.GenerateFromPassword([]byte(dummyPassword), s.cfg.BcryptCost); err == nil {
			s.dummyHash = h
		}
	})
	return s.dummyHash
}

// reportError — проглоченные ошибки (touch last_used): возвращать их
// некому, но молча терять нельзя — уходит в ErrorHook (лог в wire).
func (s *Service) reportError(err error) {
	if err != nil && s.cfg.ErrorHook != nil {
		s.cfg.ErrorHook(err)
	}
}

// authStoreError классифицирует ошибку catalog-store'а на пути
// аутентификации: отсутствие записи — штатное «не найдено» (Forbidden
// с нейтральной причиной, не раскрывающей, что именно не найдено),
// прочие сбои — недоступность каталога (503). Проглатывание
// транзиентной ошибки БД превращало сбой каталога в «неверные
// учётные данные» — мониторинг слеп, brute-force-детекторы
// дезинформированы (аудит 2026-08-27).
func authStoreError(err error, what, forbiddenReason string) error {
	var nf *domain.NotFoundError
	if errors.As(err, &nf) {
		return &domain.ForbiddenError{Reason: forbiddenReason}
	}
	return &domain.UnavailableError{What: what, Reason: "сбой каталога", Err: err}
}

// VerifyPassword returns a user only after a password comparison.
func (s *Service) VerifyPassword(ctx context.Context, username, password string) (domain.User, error) {
	u, err := s.cfg.Users.UserByUsername(ctx, username)
	if err != nil {
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			return domain.User{}, &domain.UnavailableError{What: "каталог", Reason: "чтение пользователя", Err: err}
		}
		// Несуществующий пользователь — полная стоимость bcrypt-сравнения
		// против валидного dummy-хэша (той же стоимости, что боевые):
		// перечисление пользователей по таймингу ответа не работает.
		if h := s.dummyHashBytes(); h != nil {
			_ = bcrypt.CompareHashAndPassword(h, []byte(password))
		}
		return domain.User{}, &domain.ForbiddenError{Reason: "неверные учётные данные"}
	}
	// Сравнение идёт ДО проверки длины: bcrypt семантически обрезает
	// пароль до 72 байт, и короткое замыкание по длине создавало бы
	// тайминг-оракул длины пароля. Прошедший сравнение длинный пароль
	// отклоняется явной ошибкой (аудит 2026-08-27).
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return domain.User{}, &domain.ForbiddenError{Reason: "неверные учётные данные"}
	}
	if len([]byte(password)) > maxBcryptPassword {
		return domain.User{}, &domain.TooLargeError{Size: int64(len([]byte(password))), Limit: maxBcryptPassword}
	}
	return u, nil
}

// Login verifies credentials, issues a session and records the result.
func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	// Записи auth.login не зависят от живости соединения: обрыв на
	// POST /auth/login (типично для брутфорс-скриптов) рвал request-ctx
	// вместе с записью — brute-force-детекторы слепли.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginAuditTimeout)
	defer cancel()
	u, err := s.VerifyPassword(ctx, username, password)
	if err != nil {
		// Причина в аудите различает «не подошли» и «каталог недоступен»:
		// второе — не попытка подбора, в rate-статистику не смешивается.
		detail := "invalid_credentials"
		var unavail *domain.UnavailableError
		if errors.As(err, &unavail) {
			detail = "catalog_unavailable"
		}
		s.audit(actx, username, "auth.login", "user:"+username, domain.AuditError, detail)
		return "", err
	}
	token, err := s.IssueSession(ctx, u)
	if err != nil {
		s.audit(actx, username, "auth.login", "user:"+username, domain.AuditError, "session_issue")
		return "", err
	}
	s.audit(actx, username, "auth.login", "user:"+username, domain.AuditOK, "")
	return token, nil
}

// IssueSession creates an HS256 JWT.
func (s *Service) IssueSession(_ context.Context, u domain.User) (string, error) {
	jti, err := s.cfg.Rand.UUID4()
	if err != nil {
		return "", err
	}
	now := s.cfg.Clock.Now()
	claims := jwt.MapClaims{"sub": fmt.Sprint(u.ID), "jti": jti, "ver": u.TokenVersion, "iat": now.Unix(), "exp": now.Add(s.cfg.SessionTTL).Unix()}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.JWTSecret))
}

// ValidateSession verifies signature/expiry and reloads role and version.
func (s *Service) ValidateSession(ctx context.Context, raw string) (Session, error) {
	t, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("неверный алгоритм")
		}
		return []byte(s.cfg.JWTSecret), nil
	}, jwt.WithTimeFunc(s.cfg.Clock.Now))
	if err != nil || !t.Valid {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	c, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	sub, ok := c["sub"].(string)
	if !ok {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	var id int64
	if _, err := fmt.Sscan(sub, &id); err != nil {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	ver, ok := c["ver"].(float64)
	if !ok {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	u, err := s.cfg.Users.User(ctx, id)
	if err != nil {
		// Транзиентный сбой каталога — 503-домен, а не «недействительная
		// сессия»: валидный токен не должен отклоняться молча.
		return Session{}, authStoreError(err, "каталог", "недействительная сессия")
	}
	if int64(ver) != u.TokenVersion {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	jti, _ := c["jti"].(string)
	if jti == "" {
		// Сессия без jti неотзываема (revocation покрывает все выпущенные
		// токены) — отклоняем, а не пропускаем мимо карты отзывов.
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	if s.revokedInMemory(jti) {
		return Session{}, &domain.ForbiddenError{Reason: "отозванная сессия"}
	}
	// Персистентная проверка — на каждый запрос: карта в памяти лишь
	// fast-path, источник истины после рестарта — каталог.
	yes, err := s.cfg.Revocations.IsRevoked(ctx, jti, s.cfg.Clock.Now())
	if err != nil {
		return Session{}, &domain.UnavailableError{What: "каталог", Reason: "проверка отзыва сессии", Err: err}
	}
	if yes {
		return Session{}, &domain.ForbiddenError{Reason: "отозванная сессия"}
	}
	return Session{User: u, JTI: jti}, nil
}

// RevokeSession revokes one JWT until its natural expiration: the
// revocation is persisted (logout survives a process restart) and kept
// in memory as a fast-path. A failed insert is an error — logout that
// would not survive a restart must not answer 204; in-process the
// session is revoked regardless (rememberRevoked happens before the
// return). A store failure maps to UnavailableError: logout answers
// 503 like every other auth path over a degraded catalog, not a raw
// 500 (сессия 30); доменная ошибка остаётся видна statusFor через
// errors.As сквозь обёртку.
func (s *Service) RevokeSession(ctx context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	now := s.cfg.Clock.Now()
	until := now.Add(s.cfg.SessionTTL)
	err := s.cfg.Revocations.InsertRevocation(ctx, jti, now, until)
	s.rememberRevoked(jti, until)
	if err != nil {
		return &domain.UnavailableError{What: "каталог", Reason: "запись отзыва сессии", Err: err}
	}
	return nil
}

// rememberRevoked добавляет jti в in-memory fast-path: просроченные
// записи чистятся при каждой вставке, переполнение вытесняет
// произвольную запись — персистентный слой остаётся источником истины.
func (s *Service) rememberRevoked(jti string, until time.Time) {
	s.revokedMu.Lock()
	defer s.revokedMu.Unlock()
	now := s.cfg.Clock.Now()
	for j, exp := range s.revoked {
		if !now.Before(exp) {
			delete(s.revoked, j)
		}
	}
	// Вытеснение циклом: после вставки карта не превышает потолок
	// (проверка до вставки резервирует слот).
	for len(s.revoked) >= maxRevokedMemory {
		for j := range s.revoked {
			delete(s.revoked, j)
			break
		}
	}
	s.revoked[jti] = until
}

// revokedInMemory проверяет fast-path, лениво выкидывая просроченное.
func (s *Service) revokedInMemory(jti string) bool {
	s.revokedMu.Lock()
	defer s.revokedMu.Unlock()
	until, ok := s.revoked[jti]
	if !ok {
		return false
	}
	if !s.cfg.Clock.Now().Before(until) {
		delete(s.revoked, jti)
		return false
	}
	return true
}

// InvalidateUserSessions increments the persisted session version.
func (s *Service) InvalidateUserSessions(ctx context.Context, id int64) error {
	u, err := s.cfg.Users.User(ctx, id)
	if err != nil {
		return err
	}
	u.TokenVersion++
	return s.cfg.Users.UpdateUser(ctx, u)
}

// IssueAPIToken returns the raw secret separately; it is never persisted.
func (s *Service) IssueAPIToken(ctx context.Context, u domain.User, name string, scopes []domain.Scope, ttl time.Duration) (domain.APIToken, string, error) {
	canonical := make([]domain.Scope, len(scopes))
	for i, scope := range scopes {
		var err error
		canonical[i], err = domain.NormalizeScope(string(scope))
		if err != nil {
			return domain.APIToken{}, "", err
		}
	}
	seed, err := s.cfg.Rand.UUID4()
	if err != nil {
		return domain.APIToken{}, "", err
	}
	prefix := strings.ReplaceAll(seed[:8], "-", "")
	secret := strings.ReplaceAll(seed, "-", "")
	raw := "khz_" + prefix + "_" + secret
	t := domain.APIToken{UserID: u.ID, Name: name, Prefix: prefix, SHA256: domain.HashToken(prefix + secret), Scopes: canonical, CreatedAt: s.cfg.Clock.Now()}
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(ttl)
	}
	t, err = s.cfg.Tokens.CreateToken(ctx, t)
	if err != nil {
		return domain.APIToken{}, "", err
	}
	return t, raw, nil
}

// VerifyAPIToken authenticates a raw khz token and touches its usage time.
func (s *Service) VerifyAPIToken(ctx context.Context, raw string) (domain.APIToken, domain.User, error) {
	parts := strings.Split(raw, "_")
	if len(parts) != 3 || parts[0] != "khz" || parts[1] == "" || parts[2] == "" {
		return domain.APIToken{}, domain.User{}, &domain.ForbiddenError{Reason: "недействительный API-токен"}
	}
	t, err := s.cfg.Tokens.TokenBySHA256(ctx, domain.HashToken(parts[1]+parts[2]))
	if err != nil {
		return domain.APIToken{}, domain.User{}, authStoreError(err, "каталог", "недействительный API-токен")
	}
	if subtle.ConstantTimeCompare([]byte(t.SHA256), []byte(domain.HashToken(parts[1]+parts[2]))) != 1 || !t.RevokedAt.IsZero() || (!t.ExpiresAt.IsZero() && !s.cfg.Clock.Now().Before(t.ExpiresAt)) {
		return domain.APIToken{}, domain.User{}, &domain.ForbiddenError{Reason: "недействительный API-токен"}
	}
	u, err := s.cfg.Users.User(ctx, t.UserID)
	if err != nil {
		return domain.APIToken{}, domain.User{}, authStoreError(err, "каталог", "недействительный API-токен")
	}
	if s.touchThrottled(t.ID) {
		return t, u, nil
	}
	if err := s.cfg.Tokens.TouchToken(ctx, t.ID, s.cfg.Clock.Now()); err != nil {
		// last_used — косметика: транзиентный сбой записи не отменяет
		// валидность токена (аудит 2026-08-27: отказ аутентификации из-за
		// косметической записи). Ошибка — в ErrorHook, токен валиден.
		s.reportError(fmt.Errorf("auth: touch token %d: %w", t.ID, err))
		return t, u, nil
	}
	if s.cfg.TouchInterval > 0 {
		s.touchMu.Lock()
		if len(s.lastTouch) >= maxTouchMemory {
			s.lastTouch = make(map[int64]time.Time)
		}
		s.lastTouch[t.ID] = s.cfg.Clock.Now()
		s.touchMu.Unlock()
	}
	return t, u, nil
}

// touchThrottled сообщает, что last_used для токена уже писалось недавно
// (писать чаще auth.touch_interval незачем — это запись на каждый
// запрос ради статистики).
func (s *Service) touchThrottled(id int64) bool {
	if s.cfg.TouchInterval <= 0 {
		return false
	}
	s.touchMu.Lock()
	defer s.touchMu.Unlock()
	last, ok := s.lastTouch[id]
	return ok && s.cfg.Clock.Now().Sub(last) < s.cfg.TouchInterval
}

func (s *Service) audit(ctx context.Context, actor, action, object, result, detail string) {
	if s.cfg.Audit != nil {
		_ = s.cfg.Audit.Record(ctx, domain.AuditEntry{At: s.cfg.Clock.Now(), Actor: actor, Action: action, Object: object, Result: result, Detail: detail})
	}
}
