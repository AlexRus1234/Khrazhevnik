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

-- Индекс sync_jobs(remote_id) (сессия 117, волна «Гигиена»). До него
-- JobStore.JobByRemote не мог: findJobByRemote обходил Jobs() целиком
-- с фильтром по remote — на каждый ProgressInterval=2s активного sync
-- (touchJob). Обещание ROADMAP «заодно индекс sync_jobs по remote_id».

-- +goose Up
CREATE INDEX IF NOT EXISTS idx_sync_jobs_remote_id ON sync_jobs(remote_id);

-- +goose Down
DROP INDEX IF EXISTS idx_sync_jobs_remote_id;
