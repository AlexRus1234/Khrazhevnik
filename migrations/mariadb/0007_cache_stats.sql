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

-- Снапшот per-eco счётчиков статистики кеша (сессия 95), диалект
-- mariadb: одна строка на экосистему, снапшот всегда полный.
-- updated_at — целочисленная эпоха, время приходит из port.Clock.

-- +goose Up
CREATE TABLE cache_stats (
    ecosystem           VARCHAR(64) PRIMARY KEY,
    hits                BIGINT NOT NULL DEFAULT 0,
    misses              BIGINT NOT NULL DEFAULT 0,
    stale_served        BIGINT NOT NULL DEFAULT 0,
    negative_hits       BIGINT NOT NULL DEFAULT 0,
    upstream_errors     BIGINT NOT NULL DEFAULT 0,
    bytes_from_upstream BIGINT NOT NULL DEFAULT 0,
    bytes_to_clients    BIGINT NOT NULL DEFAULT 0,
    packages            BIGINT NOT NULL DEFAULT 0,
    updated_at          BIGINT NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE cache_stats;
