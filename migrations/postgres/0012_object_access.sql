-- Хражевник — кеш-прокси и зеркало linux-репозиториев
-- Copyright (C) 2026 AlexRus1234
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published
-- by the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

-- Учёт обращений к объектам (сессия 166), диалект postgres: давность
-- обращения к конкретной версии — критерий ретеншна. Таблица общая для
-- личных репо (scope=repo) и кеш-прокси (scope=cache). last_access_at —
-- целочисленная эпоха (dbtalk.Now). key — тот же namespace ключей, что
-- у object_index (TEXT: длины ключей до domain.maxKeyLen).

-- +goose Up
CREATE TABLE object_access (
    scope          VARCHAR(16) NOT NULL,
    key            TEXT NOT NULL,
    last_access_at BIGINT NOT NULL,
    hits           BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, key)
);

-- +goose Down
DROP TABLE object_access;
