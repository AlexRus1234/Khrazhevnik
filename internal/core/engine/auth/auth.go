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
const dummyPasswordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5u4ZJ4Y2Y5xq0XG4Y2DqjF4s8wWqT6W"

// Config wires authentication to persistence and deterministic system ports.
type Config struct {
	Users      port.UserStore
	Tokens     port.TokenStore
	Audit      port.AuditLog
	Clock      port.Clock
	Rand       port.Rand
	JWTSecret  string
	SessionTTL time.Duration
}

// Service is the authentication application service.
type Service struct {
	cfg       Config
	revokedMu sync.Mutex
	revoked   map[string]time.Time
}

// New creates an authentication service.
func New(cfg Config) (*Service, error) {
	if cfg.Users == nil || cfg.Tokens == nil || cfg.Clock == nil || cfg.Rand == nil || cfg.JWTSecret == "" || cfg.SessionTTL <= 0 {
		return nil, errors.New("auth: неполная конфигурация")
	}
	return &Service{cfg: cfg, revoked: make(map[string]time.Time)}, nil
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
	if len([]byte(password)) > maxBcryptPassword {
		return domain.User{}, &domain.TooLargeError{Size: int64(len([]byte(password))), Limit: maxBcryptPassword}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// bcrypt has a hard 72-byte limit; never create an account after a hash failure.
		return domain.User{}, &domain.TooLargeError{Size: int64(len([]byte(password))), Limit: maxBcryptPassword}
	}
	u, err := s.cfg.Users.CreateUser(ctx, domain.User{Username: username, PasswordHash: string(hash), Role: role, TokenVersion: 1, CreatedAt: s.cfg.Clock.Now()})
	if err == nil {
		s.audit(ctx, username, "user.create", "user:"+username, domain.AuditOK, "")
	}
	return u, err
}

// VerifyPassword returns a user only after a password comparison.
func (s *Service) VerifyPassword(ctx context.Context, username, password string) (domain.User, error) {
	u, err := s.cfg.Users.UserByUsername(ctx, username)
	hash := dummyPasswordHash
	if err == nil {
		hash = u.PasswordHash
	}
	if len([]byte(password)) > maxBcryptPassword || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || err != nil {
		return domain.User{}, &domain.ForbiddenError{Reason: "неверные учётные данные"}
	}
	return u, nil
}

// Login verifies credentials, issues a session and records the result.
func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	u, err := s.VerifyPassword(ctx, username, password)
	if err != nil {
		s.audit(ctx, username, "auth.login", "user:"+username, domain.AuditError, "invalid_credentials")
		return "", err
	}
	token, err := s.IssueSession(ctx, u)
	if err != nil {
		s.audit(ctx, username, "auth.login", "user:"+username, domain.AuditError, "session_issue")
		return "", err
	}
	s.audit(ctx, username, "auth.login", "user:"+username, domain.AuditOK, "")
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
	if err != nil || int64(ver) != u.TokenVersion {
		return Session{}, &domain.ForbiddenError{Reason: "недействительная сессия"}
	}
	jti, _ := c["jti"].(string)
	s.revokedMu.Lock()
	revokedUntil, revoked := s.revoked[jti]
	if revoked && !s.cfg.Clock.Now().Before(revokedUntil) {
		delete(s.revoked, jti)
		revoked = false
	}
	s.revokedMu.Unlock()
	if revoked {
		return Session{}, &domain.ForbiddenError{Reason: "отозванная сессия"}
	}
	return Session{User: u, JTI: jti}, nil
}

// RevokeSession revokes one JWT in process until its natural expiration. This
// is intentionally not persistent; token_version remains the durable mass logout mechanism.
func (s *Service) RevokeSession(jti string) {
	if jti == "" {
		return
	}
	s.revokedMu.Lock()
	s.revoked[jti] = s.cfg.Clock.Now().Add(s.cfg.SessionTTL)
	s.revokedMu.Unlock()
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
		return domain.APIToken{}, domain.User{}, &domain.ForbiddenError{Reason: "недействительный API-токен"}
	}
	if subtle.ConstantTimeCompare([]byte(t.SHA256), []byte(domain.HashToken(parts[1]+parts[2]))) != 1 || !t.RevokedAt.IsZero() || (!t.ExpiresAt.IsZero() && !s.cfg.Clock.Now().Before(t.ExpiresAt)) {
		return domain.APIToken{}, domain.User{}, &domain.ForbiddenError{Reason: "недействительный API-токен"}
	}
	u, err := s.cfg.Users.User(ctx, t.UserID)
	if err != nil {
		return domain.APIToken{}, domain.User{}, &domain.ForbiddenError{Reason: "недействительный API-токен"}
	}
	if err := s.cfg.Tokens.TouchToken(ctx, t.ID, s.cfg.Clock.Now()); err != nil {
		return domain.APIToken{}, domain.User{}, err
	}
	return t, u, nil
}

func (s *Service) audit(ctx context.Context, actor, action, object, result, detail string) {
	if s.cfg.Audit != nil {
		_ = s.cfg.Audit.Record(ctx, domain.AuditEntry{At: s.cfg.Clock.Now(), Actor: actor, Action: action, Object: object, Result: result, Detail: detail})
	}
}
