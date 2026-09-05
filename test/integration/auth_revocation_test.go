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

//go:build integration

// Персистентный отзыв JWT-сессий (сессия 25): logout переживает
// «рестарт» сервиса — новый каталог на том же файле и новый auth.Service
// с чистой in-memory картой отклоняют отозванный токен (аудит
// 2026-08-27: in-memory отзыв оживал после рестарта).

package integration

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/mod/db/sqlite"
	"khrazhevnik/internal/testutil"
)

func TestLogoutRevocationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "revocation.db")
	// rand различает «процессы»: jti детерминирован FixedRand, а
	// персистентность проверки — в том, что отзыв из a1 видит a2.
	open := func(t *testing.T, seed string) *auth.Service {
		t.Helper()
		st, err := sqlite.Open(config.Database{DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		a, err := auth.New(auth.Config{
			Users: st, Tokens: st, Revocations: st,
			Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand(seed),
			JWTSecret: "secret-32-bytes-long-xxxxxxxxxx", SessionTTL: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	a1 := open(t, "11111111-1111-4111-8111-111111111111")
	if _, err := a1.CreateUser(ctx, "alice", "correct-horse", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	token, err := a1.Login(ctx, "alice", "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a1.ValidateSession(ctx, token); err != nil {
		t.Fatalf("свежевыпущенная сессия не валидна: %v", err)
	}
	if err := a1.RevokeSession(ctx, "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}

	// «Рестарт»: закрыли каталог, открыли заново, новый Service.
	a2 := open(t, "22222222-2222-4222-8222-222222222222")
	if _, err := a2.ValidateSession(ctx, token); !errors.Is(err, &domain.ForbiddenError{}) {
		t.Fatalf("отозванная сессия пережила рестарт: %v", err)
	}
	// Живой токен после рестарта работает (отзыв не перекосил валидацию).
	live, err := a2.Login(ctx, "alice", "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a2.ValidateSession(ctx, live); err != nil {
		t.Fatalf("живая сессия после рестарта: %v", err)
	}
}
