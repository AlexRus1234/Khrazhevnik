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

package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sqlite3 "modernc.org/sqlite/lib"

	"khrazhevnik/internal/contract"
	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Компиляция срезов порта: Store обязан реализовать весь каталог.
var (
	_ port.UserStore              = (*Store)(nil)
	_ port.TokenStore             = (*Store)(nil)
	_ port.RepoStore              = (*Store)(nil)
	_ port.RemoteStore            = (*Store)(nil)
	_ port.JobStore               = (*Store)(nil)
	_ port.AuditLog               = (*Store)(nil)
	_ port.ObjectIndex            = (*Store)(nil)
	_ port.SessionRevocationStore = (*Store)(nil)
)

// fixed — детерминированное время записи (эпоха теряет доли секунды).
var fixed = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// openTest — файловая БД во временном каталоге (изоляция тестов,
// проверка WAL/пула на реальном носителе).
func openTest(t *testing.T) *Store {
	t.Helper()
	return openDSN(t, filepath.Join(t.TempDir(), "test.db"))
}

// openDSN — Store по произвольному DSN.
func openDSN(t *testing.T, dsn string) *Store {
	t.Helper()
	st, err := Open(config.Database{DSN: dsn})
	if err != nil {
		t.Fatalf("Open(%s): %v", dsn, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestCatalogContract — общий контрактный suite (сессия 04 + 17) гоняет
// все срезы каталога; тот же код в test/integration гоняет postgres/
// mariadb через CI-сервисы. Здесь — в unit-покрытии sqlite.
func TestCatalogContract(t *testing.T) {
	contract.CatalogSuite(t, func(t *testing.T) contract.Catalog {
		st := openDSN(t, filepath.Join(t.TempDir(), "contract.db"))
		return contract.Catalog{
			Users:       st,
			Tokens:      st,
			Repos:       st,
			Remotes:     st,
			Jobs:        st,
			Audit:       st,
			ObjIndex:    st,
			Revocations: st,
			Close:       st.Close,
		}
	})
}

// TestRevocationsPurgeAndRestart — сессия 25: вставка отзыва чистит
// просроченные записи (гигиена одним вызовом), а «рестарт» (второй
// Store на том же файле) видит отзыв.
func TestRevocationsPurgeAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "revocations.db")
	st1 := openDSN(t, path)
	now := fixed
	if err := st1.InsertRevocation(ctx, "jti-old", now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st1.InsertRevocation(ctx, "jti-live", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Вставка с now — чистка удалила просроченный jti-old физически.
	var count int
	if err := st1.db.QueryRow(`SELECT COUNT(*) FROM revoked_sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("после чистки в таблице %d записей, хочу 1", count)
	}
	// Рестарт: новый Store на том же файле видит живой отзыв.
	st2 := openDSN(t, path)
	yes, err := st2.IsRevoked(ctx, "jti-live", now)
	if err != nil || !yes {
		t.Fatalf("отзыв после переоткрытия: %v, %v", yes, err)
	}
	if yes, err := st2.IsRevoked(ctx, "jti-old", now); err != nil || yes {
		t.Fatalf("просроченный отзыв жив: %v, %v", yes, err)
	}
}

func TestBuildDSN(t *testing.T) {
	cases := []struct{ name, dsn, wantSubstr string }{
		{"путь", "/var/lib/x.db", "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"},
		{"file-uri с запросом", "file:x?mode=memory&cache=shared", "&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"},
	}
	for _, c := range cases {
		got := buildDSN(c.dsn, 42)
		if !strings.Contains(got, c.wantSubstr) {
			t.Fatalf("%s: buildDSN = %q, не содержит %q", c.name, got, c.wantSubstr)
		}
	}
	mem := buildDSN(":memory:", 42)
	if !strings.Contains(mem, "file:mem-42?mode=memory&cache=shared") {
		t.Fatalf("память: buildDSN = %q", mem)
	}
	if buildDSN(":memory:", 1) == buildDSN(":memory:", 2) {
		t.Fatal("уникальность :memory: нарушена")
	}
}

func TestMigrationsIdempotentAndPersistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	ctx := context.Background()

	st1 := openDSN(t, path)
	if _, err := st1.CreateUser(ctx, domain.User{
		Username: "alice", PasswordHash: "h", Role: domain.RoleAdmin, CreatedAt: fixed,
	}); err != nil {
		t.Fatal(err)
	}

	// второй Open на том же файле: повторный goose.Up — no-op, данные живы
	st2 := openDSN(t, path)
	got, err := st2.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != domain.RoleAdmin || got.CreatedAt != fixed {
		t.Fatalf("после переоткрытия: %+v", got)
	}
}

func TestMemoryDSNVariants(t *testing.T) {
	ctx := context.Background()

	t.Run("двоеточие-память", func(t *testing.T) {
		st := openDSN(t, ":memory:")
		u, err := st.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "h", CreatedAt: fixed})
		if err != nil {
			t.Fatal(err)
		}
		readBack(ctx, t, st, u.ID)
	})

	t.Run("shared-cache-память", func(t *testing.T) {
		st := openDSN(t, "file:khrz-test-shared?mode=memory&cache=shared")
		u, err := st.CreateUser(ctx, domain.User{Username: "bob", PasswordHash: "h", CreatedAt: fixed})
		if err != nil {
			t.Fatal(err)
		}
		readBack(ctx, t, st, u.ID)
	})
}

// readBack — пул из 8 соединений: параллельные чтения через разные
// соединения обязаны видеть одну и ту же БД (cache=shared).
func readBack(ctx context.Context, t *testing.T, st *Store, id int64) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, err := st.User(ctx, id)
			if err != nil {
				errs <- err
				return
			}
			if u.Username == "" {
				errs <- fmt.Errorf("пустое имя пользователя из параллельного чтения")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestForeignKeysEnabled(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	// FK-прагма применяется на каждом соединении: репозиторий на
	// несуществующего владельца отклоняется БД, а не молчит
	_, err := st.CreateRepo(ctx, domain.Repo{Name: "orphan", OwnerID: 999, CreatedAt: fixed})
	var cf *domain.ConflictError
	if !errors.As(err, &cf) {
		t.Fatalf("хочу ConflictError (FK), получено: %v", err)
	}
}

// TestMapWriteCode — таблица паритета маппинга с postgres/mariadb
// (docs/func/ru/storage-db.md). Код напрямую (а не синтетический
// sqlite.Error — его поля не экспортированы).
func TestMapWriteCode(t *testing.T) {
	cases := []struct {
		name string
		code int
		want string // ожидаемый Reason; "" — «уже существует» без причины
	}{
		{"unique", sqlite3.SQLITE_CONSTRAINT_UNIQUE, ""},
		{"primary key", sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY, ""},
		{"foreign key", sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY, "нарушение внешнего ключа"},
		{"not null", sqlite3.SQLITE_CONSTRAINT_NOTNULL, "нарушение NOT NULL"},
		{"check", sqlite3.SQLITE_CONSTRAINT_CHECK, "нарушение CHECK-ограничения"},
		{"catch-all constraint", sqlite3.SQLITE_CONSTRAINT, "нарушение ограничения целостности"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cf *domain.ConflictError
			err := mapWriteCode(tc.code, "объект", "k")
			if !errors.As(err, &cf) || cf.Reason != tc.want {
				t.Fatalf("%s → Conflict(%q), получено %v", tc.name, tc.want, err)
			}
		})
	}
	if err := mapWriteCode(sqlite3.SQLITE_BUSY, "x", "y"); err != nil {
		t.Fatalf("нераспознанный код → nil (исходная ошибка вернётся из mapWrite), получено %v", err)
	}
	if err := mapWrite(errors.New("иное"), "x", "y"); err == nil {
		t.Fatal("иная ошибка не должна стать nil")
	}
}
