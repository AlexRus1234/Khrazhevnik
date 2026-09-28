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

-- Политика ретеншна личного репо (сессия 165, волна «Ретеншн-политики»).
-- Политика строго 1:1 с репозиторием — колонки рядом с квотой, без
-- отдельной таблицы (прецедент quota_bytes/quota_files в 0001).
-- 0/0 = политика выключена: существующие репо получают DEFAULT 0 и
-- ведут себя как раньше (обратная совместимость).
-- DROP COLUMN sqlite поддерживает с 3.35 (modernc — новее).

-- +goose Up
ALTER TABLE repos ADD COLUMN min_versions INTEGER NOT NULL DEFAULT 0;
ALTER TABLE repos ADD COLUMN max_age_days INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE repos DROP COLUMN max_age_days;
ALTER TABLE repos DROP COLUMN min_versions;
