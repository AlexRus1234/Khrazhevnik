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

package mariadb

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"

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
	want := "INSERT INTO object_index (`key`, storage_key, etag, size, content_type, last_modified, expires_at) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?) " +
		"ON DUPLICATE KEY UPDATE `key` = VALUES(`key`), storage_key = VALUES(storage_key), " +
		"etag = VALUES(etag), size = VALUES(size), content_type = VALUES(content_type), " +
		"last_modified = VALUES(last_modified), expires_at = VALUES(expires_at)"
	if got != want {
		t.Fatalf("objectMetaUpsertSQL =\n%s\nхочу\n%s", got, want)
	}
}

// TestOpenDSNClientFoundRows — DSN после openDSN обязан нести
// clientFoundRows=true: иначе UPDATE отдаёт changed rows и no-op
// UPDATE ложится в ложный NotFound (аудит 2026-08-27, сессия 21).
func TestOpenDSNClientFoundRows(t *testing.T) {
	dsn, err := openDSN("user:pass@tcp(127.0.0.1:3306)/khrz?parseTime=true")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ClientFoundRows {
		t.Fatalf("DSN без clientFoundRows=true: %s", dsn)
	}
}

// resultFake — sql.Result для requireAffected без БД; отражает
// matched-семантику (clientFoundRows=true): RowsAffected — число
// совпавших строк, а не изменённых.
type resultFake struct{ affected int64 }

func (resultFake) LastInsertId() (int64, error) { return 1, nil }

func (r resultFake) RowsAffected() (int64, error) { return r.affected, nil }

func TestRequireAffectedMatchedRows(t *testing.T) {
	// no-op UPDATE: строка совпала, значения не изменились — matched=1,
	// это успех, а не NotFound.
	if err := requireAffected(resultFake{affected: 1}, "remote", "x"); err != nil {
		t.Fatalf("no-op UPDATE (matched=1): %v", err)
	}
	var nf *domain.NotFoundError
	if err := requireAffected(resultFake{affected: 0}, "remote", "x"); !errors.As(err, &nf) {
		t.Fatalf("0 строк: хочу NotFoundError, получено %v", err)
	}
}

func TestRetryable(t *testing.T) {
	if !isRetryable(&mysql.MySQLError{Number: errLockDeadlock}) {
		t.Error("1213 (deadlock) должен быть retryable")
	}
	if !isRetryable(&mysql.MySQLError{Number: errLockWaitTimeout}) {
		t.Error("1205 (lock_wait_timeout) должен быть retryable")
	}
	// уникальный конфликт — НЕ retryable
	if isRetryable(&mysql.MySQLError{Number: errDupEntry}) {
		t.Error("1062 (dup) не должен быть retryable")
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
}

func TestMapWrite(t *testing.T) {
	// Таблица паритета с postgres/sqlite (docs/func/ru/storage-db.md):
	// один сценарий → один тип доменной ошибки на всех драйверах.
	cases := []struct {
		name  string
		code  uint16
		check func(*testing.T, error)
	}{
		{"dup", errDupEntry, func(t *testing.T, err error) {
			var cf *domain.ConflictError
			if !errors.As(err, &cf) || cf.Reason != "" {
				t.Fatalf("1062 → Conflict без причины, получено %v", err)
			}
		}},
		{"fk insert", errNoRefRow, wantFKConflict},
		{"fk delete", errRowReferenced, wantFKConflict},
		{"not null", errBadNull, func(t *testing.T, err error) {
			var cf *domain.ConflictError
			if !errors.As(err, &cf) || cf.Reason != "нарушение NOT NULL" {
				t.Fatalf("1048 → Conflict NOT NULL, получено %v", err)
			}
		}},
		{"check", errCheckViolated, func(t *testing.T, err error) {
			var cf *domain.ConflictError
			if !errors.As(err, &cf) || cf.Reason != "нарушение CHECK-ограничения" {
				t.Fatalf("4025 → Conflict CHECK, получено %v", err)
			}
		}},
		{"data too long", errDataTooLong, func(t *testing.T, err error) {
			var ik *domain.InvalidKeyError
			if !errors.As(err, &ik) {
				t.Fatalf("1406 → InvalidKeyError, получено %v", err)
			}
		}},
		{"wrong value", errWrongValue, func(t *testing.T, err error) {
			var ve *domain.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("1366 → ValidationError, получено %v", err)
			}
		}},
		{"неизвестный код", 1146, func(t *testing.T, err error) {
			var myErr *mysql.MySQLError
			if !errors.As(err, &myErr) {
				t.Fatalf("неизвестный код должен проходить как есть, получено %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, mapWrite(&mysql.MySQLError{Number: tc.code}, "объект", "k"))
		})
	}
	if err := mapWrite(errors.New("иное"), "x", "y"); err == nil {
		t.Fatal("иная ошибка не должна стать nil")
	}
}

// wantFKConflict — ассерт FK-ветки: Conflict с причиной про ключи.
func wantFKConflict(t *testing.T, err error) {
	t.Helper()
	var cf *domain.ConflictError
	if !errors.As(err, &cf) || cf.Reason != "нарушение внешнего ключа" {
		t.Fatalf("хочу Conflict с FK-причиной, получено %v", err)
	}
}
