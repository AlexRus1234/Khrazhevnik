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

-- Generic key-value настройки инстанса (сессия 154, волна «Прокси и
-- импорт/экспорт»), диалект postgres: пока единственный ключ —
-- upstream.proxy. updated_at — целочисленная эпоха (стиль 0007),
-- время из port.Clock.

-- +goose Up
CREATE TABLE settings (
    key        VARCHAR(64) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at BIGINT NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE settings;
