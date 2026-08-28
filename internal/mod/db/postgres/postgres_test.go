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

package postgres

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"khrazhevnik/internal/core/dbtalk"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Компиляция срезов порта: Store обязан реализовать весь каталог.
var (
	_ port.UserStore   = (*Store)(nil)
	_ port.TokenStore  = (*Store)(nil)
	_ port.RepoStore   = (*Store)(nil)
	_ port.RemoteStore = (*Store)(nil)
	_ port.JobStore    = (*Store)(nil)
	_ port.AuditLog    = (*Store)(nil)
	_ port.ObjectIndex = (*Store)(nil)
)

func TestObjectMetaUpsertSQL(t *testing.T) {
	got := objectMetaUpsertSQL()
	want := "INSERT INTO object_index (key, storage_key, etag, size, content_type, last_modified, expires_at) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7) " +
		"ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key, storage_key = EXCLUDED.storage_key, " +
		"etag = EXCLUDED.etag, size = EXCLUDED.size, content_type = EXCLUDED.content_type, " +
		"last_modified = EXCLUDED.last_modified, expires_at = EXCLUDED.expires_at"
	if got != want {
		t.Fatalf("objectMetaUpsertSQL =\n%s\nхочу\n%s", got, want)
	}
	// dbtalk.Postgres — канон $n-диалект (тут просто cross-check).
	var d dbtalk.Postgres
	if d.Placeholder(7) != "$7" {
		t.Fatal("Postgres.Placeholder(7) != $7")
	}
}

func TestRetryable(t *testing.T) {
	if !isRetryable(&pgconn.PgError{Code: "40P01"}) {
		t.Error("40P01 (deadlock) должен быть retryable")
	}
	if !isRetryable(&pgconn.PgError{Code: "55P03"}) {
		t.Error("55P03 (lock_not_available) должен быть retryable")
	}
	// уникальный конфликт — НЕ retryable (доменная ошибка)
	if isRetryable(&pgconn.PgError{Code: "23505"}) {
		t.Error("23505 (unique) не должен быть retryable")
	}
	if isRetryable(nil) || isRetryable(sql.ErrNoRows) {
		t.Error("isRetryable матчит посторонние ошибки")
	}
}

func TestMapRead(t *testing.T) {
	err := mapRead(sql.ErrNoRows, "пользователь", "x")
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("sql.ErrNoRows → хочу NotFoundError, получено %v", err)
	}
	if err := mapRead(errors.New("иное"), "пользователь", "x"); err == nil {
		t.Fatal("иная ошибка не должна маппиться в nil")
	}
}

func TestMapWrite(t *testing.T) {
	// Таблица паритета с sqlite/mariadb (docs/func/ru/storage-db.md):
	// один сценарий → один тип доменной ошибки на всех драйверах.
	cases := []struct {
		name string
		code string
		want string // ожидаемый Reason; "" — «уже существует» без причины
	}{
		{"unique", "23505", ""},
		{"fk", "23503", "нарушение внешнего ключа"},
		{"not null", "23502", "нарушение NOT NULL"},
		{"check", "23514", "нарушение CHECK-ограничения"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cf *domain.ConflictError
			err := mapWrite(&pgconn.PgError{Code: tc.code}, "объект", "k")
			if !errors.As(err, &cf) || cf.Reason != tc.want {
				t.Fatalf("%s → Conflict(%q), получено %v", tc.name, tc.want, err)
			}
		})
	}
	// неизвестный SQLSTATE и посторонняя ошибка проходят как есть
	pgErr := &pgconn.PgError{Code: "42601"}
	if err := mapWrite(pgErr, "x", "y"); !errors.As(err, &pgErr) {
		t.Fatalf("неизвестный код должен проходить как есть, получено %v", err)
	}
	if err := mapWrite(errors.New("иное"), "x", "y"); err == nil {
		t.Fatal("иная ошибка не должна стать nil")
	}
}
