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

-- Начальная схема, диалект postgres (docs/SPECIFICATION.md §БД). Перевод
-- sqlite-0001: INTEGER PK → BIGSERIAL, эпоха/размеры — BIGINT (int64
-- каталога), bool-колонки — BOOLEAN. Состав колонок и миграционная
-- история параллельны sqlite: sync-настройки remote и storage_key
-- добавятся миграциями 0003/0004 на любом драйвере.

-- +goose Up
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    token_version BIGINT NOT NULL DEFAULT 1,
    created_at    BIGINT NOT NULL
);

CREATE TABLE api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users (id),
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT,
    last_used_at BIGINT
);
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);

CREATE TABLE repos (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    owner_id    BIGINT NOT NULL REFERENCES users (id),
    ecosystem   TEXT NOT NULL,
    quota_bytes BIGINT NOT NULL DEFAULT 0,
    quota_files BIGINT NOT NULL DEFAULT 0,
    created_at  BIGINT NOT NULL
);

CREATE TABLE repo_perms (
    repo_id    BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    perm       TEXT NOT NULL DEFAULT 'write',
    created_at BIGINT NOT NULL,
    PRIMARY KEY (repo_id, user_id)
);

CREATE TABLE remotes (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    ecosystem    TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    mode         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   BIGINT NOT NULL
);

CREATE TABLE sync_jobs (
    id           BIGSERIAL PRIMARY KEY,
    remote_id    BIGINT NOT NULL REFERENCES remotes (id) ON DELETE CASCADE,
    state        TEXT NOT NULL,
    interval_sec BIGINT NOT NULL DEFAULT 0,
    last_run_at   BIGINT,
    cursor       TEXT NOT NULL DEFAULT '',
    updated_at   BIGINT NOT NULL
);

CREATE TABLE audit_log (
    id     BIGSERIAL PRIMARY KEY,
    ts     BIGINT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    object TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE TABLE object_index (
    key           TEXT PRIMARY KEY,
    etag          TEXT NOT NULL DEFAULT '',
    size          BIGINT NOT NULL DEFAULT 0,
    content_type  TEXT NOT NULL DEFAULT '',
    last_modified BIGINT,
    expires_at    BIGINT
);

-- +goose Down
DROP TABLE object_index;
DROP TABLE audit_log;
DROP TABLE sync_jobs;
DROP TABLE remotes;
DROP TABLE repo_perms;
DROP TABLE repos;
DROP TABLE api_tokens;
DROP TABLE users;
