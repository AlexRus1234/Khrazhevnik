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

// Package sqlite — каталог на embedded SQLite (modernc, CGO-free):
// пул соединений с per-conn PRAGMA через DSN, goose-миграции из
// embedded FS при старте, retry на SQLITE_BUSY. Реализации срезов
// порта каталога — в catalog.go.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/registry"
	migrations "khrazhevnik/migrations/sqlite"
)

// Пул и retry-политика (docs/SPECIFICATION.md §БД): мы сервер, не CLI —
// держим несколько соединений; busy_timeout гасит большинство локов,
// остаток добирает короткий retry с нарастающей паузой 50→200 мс.
const (
	poolMaxOpen = 8
	poolMaxIdle = 8
	busyRetries = 2
)

// init регистрирует фабрику в compile-time реестре; модуль попадает в
// бинарник blank-import'ом в cmd/khrazhevnik/wire.go. Явная сборка
// CatalogSet — заодно compile-time проверка, что Store реализует все
// срезы порта.
func init() {
	registry.RegisterDB(config.DriverSQLite, func(cfg config.Database) (registry.CatalogSet, error) {
		st, err := Open(cfg)
		if err != nil {
			return registry.CatalogSet{}, err
		}
		return registry.CatalogSet{
			Users:       st,
			Tokens:      st,
			Repos:       st,
			Remotes:     st,
			Jobs:        st,
			Audit:       st,
			ObjIndex:    st,
			Revocations: st,
		}, nil
	})
}

// Store — один *sql.DB, реализующий все срезы порта каталога.
// sleep вынесен в поле для тестов retry без реальных пауз.
type Store struct {
	db    *sql.DB
	sleep func(time.Duration)
	// upsertObjectMeta/upsertRevocation — upsert'ы, собранные через
	// dbtalk.Upsert один раз при открытии (SQL-константы — для
	// остального; upsert — предмет диалект-шима).
	upsertObjectMeta string
	upsertRevocation string
}

// Open открывает БД по cfg.DSN, применяет миграции и возвращает Store.
// DSN: путь к файлу, «file:…?…» URI или «:memory:» (последний
// разворачивается в уникальную shared-cache память, иначе соединения
// пула видели бы разные пустые БД).
func Open(cfg config.Database) (*Store, error) {
	// time.Now напрямую, минуя port.Clock — осознанное исключение
	// (ревю 2026-09-06): нонс различает «:memory:»-базы одного
	// процесса, это не доменное время; clock-параметр только в sqlite
	// сломал бы симметрию Open-сигнатур трёх драйверов.
	db, err := sql.Open("sqlite", buildDSN(cfg.DSN, time.Now().UnixNano()))
	if err != nil {
		return nil, fmt.Errorf("sqlite: открытие каталога: %w", err)
	}
	db.SetMaxOpenConns(poolMaxOpen)
	db.SetMaxIdleConns(poolMaxIdle)
	// ConnMaxLifetime/ConnMaxIdleTime не выставляем осознанно: база
	// локальная (файл/память) — коннекты не рвутся firewall-таймаутами,
	// а пересоздание соединений только сбрасывало бы PRAGMA-состояние
	// (busy_timeout/foreign_keys/WAL) без выигрыша.
	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{
		db:               db,
		sleep:            time.Sleep,
		upsertObjectMeta: objectMetaUpsertSQL(),
		upsertRevocation: revocationUpsertSQL(),
	}, nil
}

// Close освобождает пул соединений (graceful shutdown).
func (s *Store) Close() error { return s.db.Close() }

// migrate поднимает embedded-миграции goose; Up идемпотентен — второй
// запуск на актуальной схеме — no-op.
func migrate(ctx context.Context, db *sql.DB) error {
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("sqlite: провайдер миграций: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("sqlite: миграции: %w", err)
	}
	return nil
}

// buildDSN дополняет DSN per-conn PRAGMA через «_pragma=» (общая форма
// modernc, работает во всех версиях драйвера): busy_timeout 5с идёт
// первым, затем foreign_keys и WAL. uniq различает «:memory:»-базы
// одного процесса.
func buildDSN(dsn string, uniq int64) string {
	const pragmas = "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	switch {
	case dsn == ":memory:":
		return fmt.Sprintf("file:mem-%d?mode=memory&cache=shared&%s", uniq, pragmas)
	case strings.Contains(dsn, "?"):
		return dsn + "&" + pragmas
	default:
		return dsn + "?" + pragmas
	}
}

// call — обёртка всех запросов каталога: до 3 попыток (1 + busyRetries)
// при SQLITE_BUSY/LOCKED с паузами 50/200 мс. Отдельная функция, а не
// метод: дженерики запрещены в методах.
func call[T any](ctx context.Context, s *Store, fn func() (T, error)) (T, error) {
	for attempt := 0; ; attempt++ {
		v, err := fn()
		if err == nil || !isBusy(err) || attempt >= busyRetries {
			return v, err
		}
		s.sleep(busyPause(attempt))
		if err := ctx.Err(); err != nil {
			return v, err
		}
	}
}

// busyPause — нарастающая пауза между попытками: 50 мс, затем 200 мс.
func busyPause(attempt int) time.Duration {
	if attempt == 0 {
		return 50 * time.Millisecond
	}
	return 200 * time.Millisecond
}

// isBusy распознаёт SQLITE_BUSY* и SQLITE_LOCKED* (включая расширенные
// коды shared-cache/snapshot) от modernc.
func isBusy(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	switch serr.Code() {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_BUSY_SNAPSHOT, sqlite3.SQLITE_BUSY_TIMEOUT,
		sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_LOCKED_SHAREDCACHE:
		return true
	}
	return false
}
