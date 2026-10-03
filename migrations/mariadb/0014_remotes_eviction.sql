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

-- Политика eviction кеш-прокси для upstream (сессия 198, волна
-- «Eviction кеш-прокси»), диалект mariadb. Политика строго 1:1 с
-- remote — колонки рядом с остальными полями, без отдельной таблицы
-- (прецедент 0011 repos). ПОЧЕМУ NULL, А НЕ 0 (в отличие от 0011 с
-- DEFAULT 0): политика tri-state — NULL = наследовать глобальный дефолт
-- конфига [eviction], 0/0 = «явно выключено» для этого remote. DEFAULT 0
-- стёр бы разницу между «наследовать» и «выключено»; существующие строки
-- получают NULL и ведут себя как раньше (обратная совместимость — дефолт
-- выключен).

-- +goose Up
ALTER TABLE remotes ADD COLUMN eviction_min_versions INT NULL;
ALTER TABLE remotes ADD COLUMN eviction_max_age_days INT NULL;

-- +goose Down
ALTER TABLE remotes DROP COLUMN eviction_max_age_days;
ALTER TABLE remotes DROP COLUMN eviction_min_versions;
