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

// Package dbtalk — общий мини-шим SQL-диалектов каталога (НЕ в mod):
// один и тот же переносимый SQL из mod/db/* отличается только
// плейсхолдерами и синтаксисом upsert. Реестр диалектов: SQLite
// (modernc), Postgres (pgx), MariaDB (go-sql-driver).
package dbtalk

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Dialect — различия SQL-диалектов, достаточные для переносимого
// каталога. Реализации — типы без состояния: каждый адаптер БД
// (mod/db/*) держит свой диалект и собирает через него upsert.
type Dialect interface {
	// Placeholder возвращает плейсхолдер аргумента номер n (с 1):
	// sqlite/mariadb — «?», postgres — «$n».
	Placeholder(n int) string
	// UpsertSuffix — хвост INSERT после VALUES (…): как превратить
	// конфликт уникальности key в обновление колонок cols.
	UpsertSuffix(key string, cols []string) string
}

// SQLite — диалект sqlite (modernc): «?» и ON CONFLICT … DO UPDATE.
type SQLite struct{}

// Placeholder возвращает «?» — позиционные аргументы sqlite.
func (SQLite) Placeholder(int) string { return "?" }

// UpsertSuffix строит «ON CONFLICT (key) DO UPDATE SET col=excluded.col, …».
func (SQLite) UpsertSuffix(key string, cols []string) string {
	sets := make([]string, len(cols))
	for i, col := range cols {
		sets[i] = col + " = excluded." + col
	}
	return fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s", key, strings.Join(sets, ", "))
}

// Postgres — диалект postgres (pgx): нумерованные плейсхолдеры «$n» и
// ON CONFLICT … DO UPDATE SET col=EXCLUDED.col (канонический регистр
// postgres; lowercase excluded тоже валиден, но EXCLUDED — устоявшийся
// стиль документации).
type Postgres struct{}

// Placeholder возвращает «$n» — нумерованные аргументы postgres.
func (Postgres) Placeholder(n int) string { return "$" + strconv.Itoa(n) }

// UpsertSuffix строит «ON CONFLICT (key) DO UPDATE SET col=EXCLUDED.col, …».
func (Postgres) UpsertSuffix(key string, cols []string) string {
	sets := make([]string, len(cols))
	for i, col := range cols {
		sets[i] = col + " = EXCLUDED." + col
	}
	return fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s", key, strings.Join(sets, ", "))
}

// MariaDB — диалект mariadb (go-sql-driver): «?» (позиционные, как
// sqlite) и ON DUPLICATE KEY UPDATE col=VALUES(col). Row-alias
// («VALUES (...) AS new») — синтаксис MySQL 8.0.19+, в MariaDB его
// нет (грамматика INSERT не допускает alias; проверено mariadb:11 в
// CI — Error 1064 у «AS new»). VALUES(col) — каноническая форма
// MariaDB (дока KB называет её актуальной для всех версий, включая 11).
// MySQL-кластеры — не-цель v1: миграции (TEXT DEFAULT) и так требуют
// MariaDB.
type MariaDB struct{}

// Placeholder возвращает «?» — позиционные аргументы mysql/mariadb.
func (MariaDB) Placeholder(int) string { return "?" }

// UpsertSuffix строит «ON DUPLICATE KEY UPDATE col = VALUES(col), …».
func (MariaDB) UpsertSuffix(_ string, cols []string) string {
	sets := make([]string, len(cols))
	for i, col := range cols {
		sets[i] = col + " = VALUES(" + col + ")"
	}
	return "ON DUPLICATE KEY UPDATE " + strings.Join(sets, ", ")
}

// Upsert собирает полный INSERT-upsert по диалекту: таблица table,
// конфликт по колонке key, колонки cols (в sqlite key и так не
// обновляется: excluded.key совпадает с конфликтующим значением).
func Upsert(d Dialect, table, key string, cols []string) string {
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = d.Placeholder(i + 1)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) %s",
		table, strings.Join(cols, ", "), strings.Join(placeholders, ", "),
		d.UpsertSuffix(key, cols))
}

// Now — каноническое преобразование времени в формат временных колонок
// каталога: целочисленная эпоха Unix в секундах. Нулевое время
// отображается в NULL на стороне адаптера.
func Now(t time.Time) int64 { return t.Unix() }
