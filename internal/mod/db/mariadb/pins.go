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

// Реализация port.PinStore — пины ретеншна личных репо (repo_pins).
// Копия sqlite-адаптера; upsert — форма MariaDB (ON DUPLICATE KEY
// UPDATE … = сама колонка: row-alias «AS new» в MariaDB нет — Error 1064).
// `key` в backticks — как в 0012 (KEY — зарезервированное слово). Обе
// операции идемпотентны; created_at не передаётся — значение берёт
// носитель (DEFAULT в 0013).

package mariadb

import (
	"context"
	"strconv"
)

// SQL пинов (repo_pins).
const (
	// sqlPinsByRepo — выборка ключей репо, порядок по key (детерминизм
	// ответа движка и тестов).
	sqlPinsByRepo = "SELECT `key` FROM repo_pins WHERE repo_id = ? ORDER BY `key`"
	// sqlPinSet — постановка пина: повторная — no-op, а не ошибка
	// (контракт порта). Присваивание колонке её же значения — форма
	// «ничего не менять»: INSERT IGNORE гасил бы и FK-нарушение
	// (чужой repo_id) — молчаливая потеря пина.
	sqlPinSet = "INSERT INTO repo_pins (repo_id, `key`) VALUES (?, ?)\n" +
		"ON DUPLICATE KEY UPDATE repo_id = repo_id"
	sqlPinDelete = "DELETE FROM repo_pins WHERE repo_id = ? AND `key` = ?"
)

// Pins отдаёт ключи, закреплённые в репозитории; пусто без ошибки.
func (s *Store) Pins(ctx context.Context, repoID int64) ([]string, error) {
	keys, err := call(ctx, s, func() ([]string, error) {
		rows, err := s.db.QueryContext(ctx, sqlPinsByRepo, repoID)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return nil, err
			}
			out = append(out, k)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, mapRead(err, "пины", strconv.FormatInt(repoID, 10))
	}
	return keys, nil
}

// SetPin ставит или снимает пин; идемпотентно в обе стороны.
func (s *Store) SetPin(ctx context.Context, repoID int64, key string, pinned bool) error {
	query := sqlPinDelete
	if pinned {
		query = sqlPinSet
	}
	// Снятие — обычный DELETE: 0 затронутых строк это успех
	// (идемпотентность), поэтому s.exec/requireAffected не годятся.
	_, err := call(ctx, s, func() (struct{}, error) {
		_, err := s.db.ExecContext(ctx, query, repoID, key)
		return struct{}{}, err
	})
	if err != nil {
		return mapWrite(err, "пин", strconv.FormatInt(repoID, 10)+"/"+key)
	}
	return nil
}
