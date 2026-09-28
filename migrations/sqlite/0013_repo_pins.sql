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

-- Пины ретеншна (сессия 170, волна «Ретеншн-политики»): закреплённая
-- версия не удаляется политикой. Строковая таблица, не колонка: пины —
-- точечные исключения по КЛЮЧУ ХРАНИЛИЩА (repo/<id>/<eco>/…), ключей у
-- объекта бывает много (версии, индексы), а закрепляют конкретную
-- версию; прецедент repo_perms — узкая таблица под узкий факт.
-- CASCADE на repo_id как у repo_perms (0001): удаление репо уносит пины,
-- иначе они жили бы вечно и указывали в никуда. created_at — эпоха Unix
-- (стиль 0007), значение — часы НОСИТЕЛЯ (DEFAULT-выражение): у порта
-- PinStore (решение владельца, сессия 170) нет параметра времени, а тащить
-- port.Clock в драйверы за диагностической меткой — лишняя связность;
-- смысл колонки — «когда закрепили», сортировка идёт по key. Порядок
-- выдачи — по key.

-- +goose Up
CREATE TABLE repo_pins (
    repo_id    INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (repo_id, key)
);

-- +goose Down
DROP TABLE repo_pins;
