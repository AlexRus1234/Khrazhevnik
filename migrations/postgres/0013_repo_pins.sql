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

-- Пины ретеншна (сессия 170), диалект postgres: закреплённая версия не
-- удаляется политикой. Строковая таблица по ключу хранилища
-- (repo/<id>/<eco>/…), прецедент repo_perms; CASCADE на repo_id — пины
-- удалённого репо не остаются. created_at — целочисленная эпоха, значение
-- из часов носителя (DEFAULT): у порта PinStore нет параметра времени, а
-- port.Clock в драйвере ради диагностической метки — лишняя связность.
-- key — тот же namespace ключей, что у object_access.

-- +goose Up
CREATE TABLE repo_pins (
    repo_id    BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    PRIMARY KEY (repo_id, key)
);

-- +goose Down
DROP TABLE repo_pins;
