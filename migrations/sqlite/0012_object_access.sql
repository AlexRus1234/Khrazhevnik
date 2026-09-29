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

-- Учёт обращений к объектам (сессия 166, волна «Ретеншн-политики»).
-- Критерий удаления ретеншна — давность обращения к конкретной версии;
-- пофайлового учёта в проекте нет (статистика агрегатная per-eco,
-- object_index — точечный лукап mutable-меты кеша, агрегаты чужой
-- задачи его раздували бы). Таблица ОБЩАЯ для личных репо (scope=repo)
-- и кеш-прокси (scope=cache): пишем для обоих, используем для репо;
-- eviction следующей волны переиспользует. Отдельная таблица — не
-- колонка в object_index (прецедент cache_stats, сессия 95).
-- Время одно — last_access_at (эпоха Unix, dbtalk.Now), updated_at-колонки
-- нет. Индексов сверх PK нет: чтение — по префиксу key в рамках scope,
-- PK-скана с фильтром достаточно (объём — тысячи строк).

-- +goose Up
CREATE TABLE object_access (
    scope          TEXT NOT NULL,
    key            TEXT NOT NULL,
    last_access_at INTEGER NOT NULL,
    hits           BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, key)
);

-- +goose Down
DROP TABLE object_access;
