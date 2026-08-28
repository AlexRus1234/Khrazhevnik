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

// Package postgres — каталог на внешнем postgres (jackc/pgx/v5 через
// database/sql-шим stdlib, goose-миграции из embedded FS при старте).
// MVCC гасит большую часть конкурентных доступов; остаток — короткий
// retry на дедлок/lock_not_available. Реализации срезов порта
// каталога — в catalog.go (те же запросы, что у sqlite, отличия —
// нумерованные плейсхолдеры $n и ON CONFLICT … DO UPDATE SET col=
// EXCLUDED.col через dbtalk.Postgres).
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/registry"
	migrations "khrazhevnik/migrations/postgres"
)

// Пул (docs/SPECIFICATION.md §БД): postgres — настоящий сервер,
// держим несколько соединений. retry — на редкие дедлоки/lock-таймауты
// (40P01 deadlock_detected, 55P03 lock_not_available); MVCC большую
// часть конфликтов разрешает ожиданием, а не отбоем.
const (
	poolMaxOpen = 8
	poolMaxIdle = 8
	retryMax    = 2
)

// init регистрирует фабрику в compile-time реестре; модуль попадает в
// бинарник blank-import'ом в cmd/khrazhevnik/wire.go.
func init() {
	registry.RegisterDB(config.DriverPostgres, func(cfg config.Database) (registry.CatalogSet, error) {
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

// Open парсит DSN (pgx), открывает пул и поднимает миграции. DSN —
// стандартная postgres-строка (postgres://user:pass@host/db?… или
// key=value). Парсинг на Open — fail-fast на плохом DSN.
func Open(cfg config.Database) (*Store, error) {
	pgCfg, err := pgx.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: разбор DSN: %w", err)
	}
	db := stdlib.OpenDB(*pgCfg)
	db.SetMaxOpenConns(poolMaxOpen)
	db.SetMaxIdleConns(poolMaxIdle)
	// Lifetime-ы обязательны: postgres — внешний сервер за возможными
	// firewall/NAT-таймаутами; без них пул держит бессмертные коннекты,
	// которые умирают посреди запроса.
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)
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

// Close освобождает пул соединений (graceful shutdown).
func (s *Store) Close() error { return s.db.Close() }

// migrate поднимает embedded-миграции goose; Up идемпотентен.
func migrate(ctx context.Context, db *sql.DB) error {
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("postgres: провайдер миграций: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("postgres: миграции: %w", err)
	}
	return nil
}

// call — обёртка запросов каталога: до 3 попыток (1 + retryMax) при
// дедлоке/lock_not_available с паузами 50/200 мс. Дружелюбные
// конфликты (23505 unique, 23503 FK) НЕ ретраятся — это доменные
// ошибки, а не конкурентность.
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

// isRetryable распознаёт дедлок (40P01) и lock_not_available (55P03).
func isRetryable(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "40P01", "55P03":
		return true
	}
	return false
}
