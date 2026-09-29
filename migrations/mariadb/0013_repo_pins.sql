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

-- Пины ретеншна (сессия 170), диалект mariadb: закреплённая версия не
-- удаляется политикой. Строковая таблица по ключу хранилища
-- (repo/<id>/<eco>/…), прецедент repo_perms; CASCADE на repo_id — пины
-- удалённого репо не остаются. created_at — целочисленная эпоха, значение
-- из часов носителя (DEFAULT): у порта PinStore нет параметра времени, а
-- port.Clock в драйвере ради диагностической метки — лишняя связность.
-- `key` — VARCHAR(512) и НЕ TEXT: предел составного PK utf8mb4 InnoDB —
-- 3072 байта, 8 (BIGINT) + 512*4 = 2056 с запасом влезает (та же причина,
-- что в 0012 object_access; TEXT дал бы Error 1071 — ключ без длины).

-- +goose Up
CREATE TABLE repo_pins (
    repo_id    BIGINT NOT NULL,
    `key`      VARCHAR(512) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (repo_id, `key`),
    FOREIGN KEY (repo_id) REFERENCES repos (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- +goose Down
DROP TABLE repo_pins;
