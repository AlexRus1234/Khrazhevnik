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
// плейсхолдерами и синтаксисом upsert. Сейчас здесь только sqlite;
// postgres/mariadb добавят свои варианты в реестр диалектов (сессия 17).
package dbtalk

import (
	"fmt"
	"strings"
	"time"
)

// Dialect — различия SQL-диалектов, достаточные для переносимого
// каталога. Реализации — типы без состояния: реестр диалектов
// (сессия 17) будет отображать имя драйвера → Dialect.
type Dialect interface {
	// Placeholder возвращает плейсхолдер аргумента номер n (с 1):
	// sqlite — «?», postgres — «$n».
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
