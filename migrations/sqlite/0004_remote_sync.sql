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

-- Sync-настройки remote (сессия 11): период авто-sync для зеркал и
-- фильтр включаемых дистрибутивов/компонент. sync_interval_sec=0 —
-- только ручной sync; include — разделённый запятыми список (для apt
-- «stable», «stable/main»; для rpm-md колонка не используется, но
-- хранится как есть для будущих экосистем).

-- +goose Up
ALTER TABLE remotes ADD COLUMN sync_interval_sec INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remotes ADD COLUMN include TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE remotes DROP COLUMN include;
ALTER TABLE remotes DROP COLUMN sync_interval_sec;
