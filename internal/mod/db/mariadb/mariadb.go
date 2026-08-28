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

// Package mariadb — каталог на внешнем mariadb (go-sql-driver/mysql),
// goose-миграции из embedded FS при старте. Плейсхолдеры — позиционные
// «?» (как sqlite), upsert — ON DUPLICATE KEY UPDATE col=VALUES(col),
// INSERT возвращает id через LastInsertId (RETURNING у драйвера не
// читается надёжно). Реализации срезов порта каталога — в catalog.go.
package mariadb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/registry"
	migrations "khrazhevnik/migrations/mariadb"
)

// Пул и retry (docs/SPECIFICATION.md §БД): mariadb — настоящий сервер,
// держим несколько соединений. retry — на редкие дедлок/lock-таймаут
// (1213 deadlock, 1205 lock_wait_timeout); InnoDB гасит конфликты
// ожиданием, но таймауты ловим коротким retry.
const (
	poolMaxOpen = 8
	poolMaxIdle = 8
	retryMax    = 2
)

// MySQL-коды ошибок (драйвер не экспортирует константы — имена из
// документации MariaDB/MySQL).
const (
	errDupEntry        uint16 = 1062 // ER_DUP_ENTRY: UNIQUE-нарушение
	errNoRefRow        uint16 = 1452 // ER_NO_REFERENCED_ROW_2: FK на INSERT
	errRowReferenced   uint16 = 1451 // ER_ROW_IS_REFERENCED_2: FK на DELETE
	errLockDeadlock    uint16 = 1213 // ER_LOCK_DEADLOCK
	errLockWaitTimeout uint16 = 1205 // ER_LOCK_WAIT_TIMEOUT
	errBadNull         uint16 = 1048 // ER_BAD_NULL_ERROR: NOT NULL
	errCheckViolated   uint16 = 4025 // ER_CHECK_CONSTRAINT_VIOLATED
	errDataTooLong     uint16 = 1406 // ER_DATA_TOO_LONG: длиннее колонки
	errWrongValue      uint16 = 1366 // ER_TRUNCATED_WRONG_VALUE: тип значения
)

// init регистрирует фабрику в compile-time реестре.
func init() {
	registry.RegisterDB(config.DriverMariaDB, func(cfg config.Database) (registry.CatalogSet, error) {
		st, err := Open(cfg)
		if err != nil {
			return registry.CatalogSet{}, err
		}
		return registry.CatalogSet{
			Users:    st,
			Tokens:   st,
			Repos:    st,
			Remotes:  st,
			Jobs:     st,
			Audit:    st,
			ObjIndex: st,
		}, nil
	})
}

// Store — один *sql.DB, реализующий все срезы порта каталога. sleep
// вынесен в поле для тестов retry без реальных пауз.
type Store struct {
	db               *sql.DB
	sleep            func(time.Duration)
	upsertObjectMeta string
}

// Open парсит DSN (mysql.ParseDSN — fail-fast на плохом формате),
// открывает пул и поднимает миграции. DSN — стандартная mysql-строка
// (user:pass@tcp(host:3306)/db?params…).
func Open(cfg config.Database) (*Store, error) {
	dsn, err := openDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mariadb: открытие каталога: %w", err)
	}
	db.SetMaxOpenConns(poolMaxOpen)
	db.SetMaxIdleConns(poolMaxIdle)
	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{
		db:               db,
		sleep:            time.Sleep,
		upsertObjectMeta: objectMetaUpsertSQL(),
	}, nil
}

// openDSN нормализует DSN с clientFoundRows=true: без этого флага
// UPDATE отдаёт changed rows, и no-op UPDATE (пересохранение тех же
// значений) выглядит как 0 затронутых строк — requireAffected
// превращал бы его в ложный NotFound (404 в админке). С флагом
// RowsAffected = matched — семантика sqlite/postgres.
func openDSN(dsn string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("mariadb: разбор DSN: %w", err)
	}
	cfg.ClientFoundRows = true
	return cfg.FormatDSN(), nil
}

// Close освобождает пул соединений (graceful shutdown).
func (s *Store) Close() error { return s.db.Close() }

// migrate поднимает embedded-миграции goose; Up идемпотентен.
func migrate(ctx context.Context, db *sql.DB) error {
	provider, err := goose.NewProvider(goose.DialectMySQL, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("mariadb: провайдер миграций: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("mariadb: миграции: %w", err)
	}
	return nil
}

// call — обёртка запросов каталога: до 3 попыток (1 + retryMax) при
// дедлоке/lock-таймауте с паузами 50/200 мс. UNIQUE/FK-конфликты НЕ
// ретраятся — это доменные ошибки.
func call[T any](ctx context.Context, s *Store, fn func() (T, error)) (T, error) {
	for attempt := 0; ; attempt++ {
		v, err := fn()
		if err == nil || !isRetryable(err) || attempt >= retryMax {
			return v, err
		}
		s.sleep(retryPause(attempt))
		if err := ctx.Err(); err != nil {
			return v, err
		}
	}
}

// retryPause — нарастающая пауза между попытками: 50 мс, затем 200 мс.
func retryPause(attempt int) time.Duration {
	if attempt == 0 {
		return 50 * time.Millisecond
	}
	return 200 * time.Millisecond
}

// isRetryable распознаёт дедлок (1213) и lock_wait_timeout (1205).
func isRetryable(err error) bool {
	var myErr *mysql.MySQLError
	if !errors.As(err, &myErr) {
		return false
	}
	switch myErr.Number {
	case errLockDeadlock, errLockWaitTimeout:
		return true
	}
	return false
}
