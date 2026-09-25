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

// Реализация port.UpstreamProxyStore — глобальный прокси исходящих
// запросов (settings, ключ upstream.proxy). Запросы — копия sqlite-
// адаптера; `key` в бэктиках — зарезервированное слово MariaDB
// (как `key` в object_index). Значение никто не читает до сессии 156
// (включение в doer-фабрику).

package mariadb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"khrazhevnik/internal/core/dbtalk"
)

// settingsProxyKey — пока единственный ключ таблицы settings.
const settingsProxyKey = "upstream.proxy"

// Настройка прокси (settings).
const sqlSettingsProxyGet = `SELECT value FROM settings WHERE ` + "`key`" + ` = ?`

// settingsUpsertSQL — upsert settings через диалект-шим; собирается
// один раз при открытии Store (прецедент upsertObjectMeta).
func settingsUpsertSQL() string {
	return dbtalk.Upsert(dbtalk.MariaDB{}, "settings", "`key`",
		[]string{"`key`", "value", "updated_at"})
}

// UpstreamProxy возвращает сохранённый прокси; нет строки — "" без
// ошибки (настройка ещё не задавалась).
func (s *Store) UpstreamProxy(ctx context.Context) (string, error) {
	return call(ctx, s, func() (string, error) {
		var v string
		err := s.db.QueryRowContext(ctx, sqlSettingsProxyGet, settingsProxyKey).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return v, err
	})
}

// SetUpstreamProxy сохраняет URL прокси (upsert: перезапись значения и
// updated_at одним стейтментом).
func (s *Store) SetUpstreamProxy(ctx context.Context, value string, at time.Time) error {
	_, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, s.upsertSettings, settingsProxyKey, value, dbtalk.Now(at))
	})
	if err != nil {
		return mapWrite(err, "настройка", settingsProxyKey)
	}
	return nil
}
