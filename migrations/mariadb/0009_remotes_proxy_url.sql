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

-- Персистентный прокси у Remote (сессия 153, волна «Прокси и
-- импорт/экспорт»), диалект mariadb: VARCHAR вместо TEXT (стиль
-- драйвера, 0007). Пустая строка = прямое соединение без прокси;
-- существующие remote'ы получают DEFAULT ''.

-- +goose Up
ALTER TABLE remotes ADD COLUMN proxy_url VARCHAR(2048) NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE remotes DROP COLUMN proxy_url;
