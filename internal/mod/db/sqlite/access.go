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

// Реализация port.AccessStore — учёт обращений к объектам (object_access).
// SQL собран по диалекту явно, а не через dbtalk.Upsert: шим выражает
// только «col = excluded.col», а мёржу нужны вычисляемые SET-выражения
// (MAX времени и сложение hits) — предмет диалекта (у mariadb своя форма
// VALUES(col)). Пофайлового учёта до этой таблицы в проекте не было.

package sqlite

import (
	"context"
	"database/sql"
	"iter"
	"strings"
	"time"

	"khrazhevnik/internal/core/dbtalk"
	"khrazhevnik/internal/core/domain"
)

// SQL учёта обращений (object_access).
const (
	// sqlAccessUpsert — мёрж пачки: время не откатывается назад (MAX
	// старого и нового), hits складываются. MAX — скалярная форма
	// sqlite (два аргумента); имя таблицы в выражении — существующая
	// строка, excluded — предлагаемая к вставке.
	sqlAccessUpsert = `INSERT INTO object_access (scope, key, last_access_at, hits) VALUES (?, ?, ?, ?)
ON CONFLICT (scope, key) DO UPDATE SET
    last_access_at = MAX(object_access.last_access_at, excluded.last_access_at),
    hits = object_access.hits + excluded.hits`
	// sqlAccessByPrefix — чтение по префиксу key в рамках scope, порядок
	// по key (курсор rows без OFFSET). «!» — ESCAPE-символ: «_» в ключах
	// обычное дело (имена пакетов/файлов), без экранирования он совпал
	// бы с любым символом; «!» в ключах не встречается (charset
	// domain.ValidateKey), но экранируется наравне.
	sqlAccessByPrefix = `SELECT scope, key, last_access_at, hits FROM object_access
WHERE scope = ? AND key LIKE ? ESCAPE '!' ORDER BY key`
	sqlAccessEntry = `SELECT scope, key, last_access_at, hits FROM object_access WHERE scope = ? AND key = ?`
)

// MergeAccess применяет пачку обращений одной транзакцией: читатель в
// другом соединении видит либо старое состояние, либо новое — не смесь
// по строчкам. Пустой срез — no-op (без похода в БД).
func (s *Store) MergeAccess(ctx context.Context, rows []domain.ObjectAccess) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := call(ctx, s, func() (sql.Result, error) {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }() // после Commit — no-op
		for _, a := range rows {
			if _, err := tx.ExecContext(ctx, sqlAccessUpsert,
				a.Scope, a.Key, dbtalk.Now(a.LastAccess), a.Hits); err != nil {
				return nil, err
			}
		}
		return nil, tx.Commit()
	})
	if err != nil {
		// Ключ первой строки — контекст доменной ошибки (сбой батча не
		// привязан к строке; точная строка не нужна потребителю).
		return mapWrite(err, "обращения к объектам", accessKey(rows[0]))
	}
	return nil
}

// AccessByPrefix отдаёт записи scope с префиксом key, по возрастанию
// key; ошибка в потоке — терминальная (обход прекращается).
func (s *Store) AccessByPrefix(ctx context.Context, scope, prefix string) (iter.Seq2[domain.ObjectAccess, error], error) {
	rows, err := s.db.QueryContext(ctx, sqlAccessByPrefix, scope, likePrefix(prefix))
	if err != nil {
		return nil, mapRead(err, "обращения к объектам", scope+"/"+prefix)
	}
	return func(yield func(domain.ObjectAccess, error) bool) {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			a, err := scanAccess(rows)
			if err != nil {
				yield(domain.ObjectAccess{}, err)
				return
			}
			if !yield(a, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(domain.ObjectAccess{}, err)
		}
	}, nil
}

// AccessEntry — точечный лукап записи; отсутствие — NotFound.
func (s *Store) AccessEntry(ctx context.Context, scope, key string) (domain.ObjectAccess, error) {
	a, err := call(ctx, s, func() (domain.ObjectAccess, error) {
		return scanAccess(s.db.QueryRowContext(ctx, sqlAccessEntry, scope, key))
	})
	if err != nil {
		return domain.ObjectAccess{}, mapRead(err, "обращения к объектам", scope+"/"+key)
	}
	return a, nil
}

// scanAccess читает строку object_access (last_access_at — эпоха Unix).
func scanAccess(row interface{ Scan(dest ...any) error }) (domain.ObjectAccess, error) {
	var a domain.ObjectAccess
	var lastAccess int64
	if err := row.Scan(&a.Scope, &a.Key, &lastAccess, &a.Hits); err != nil {
		return domain.ObjectAccess{}, err
	}
	a.LastAccess = time.Unix(lastAccess, 0).UTC()
	return a, nil
}

// likePrefix — LIKE-шаблон префиксного чтения: «%», «_» и сам ESCAPE-
// символ экранируются, в хвост — «%».
func likePrefix(prefix string) string {
	var b strings.Builder
	b.Grow(len(prefix) + 1)
	for _, r := range prefix {
		if r == '%' || r == '_' || r == '!' {
			b.WriteByte('!')
		}
		b.WriteRune(r)
	}
	b.WriteByte('%')
	return b.String()
}

// accessKey — ключ контекста доменной ошибки «scope/key».
func accessKey(a domain.ObjectAccess) string { return a.Scope + "/" + a.Key }
