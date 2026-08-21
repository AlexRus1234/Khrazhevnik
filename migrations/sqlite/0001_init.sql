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

-- Начальная схема (docs/SPECIFICATION.md §БД). Время — эпоха Unix в
-- секундах (dbtalk.Now); NULL в опциональных временных колонках —
-- «никогда»/нулевое время домена. Состав колонок следует моделям
-- internal/core/domain: поля без доменного соответствия (прогресс
-- sync-задач, disabled-флаги) добавятся своими миграциями, когда
-- появятся потребители.

-- +goose Up
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);

CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id),
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER
);
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);

CREATE TABLE repos (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    owner_id    INTEGER NOT NULL REFERENCES users (id),
    ecosystem   TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    quota_files INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE repo_perms (
    repo_id    INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    perm       TEXT NOT NULL DEFAULT 'write',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (repo_id, user_id)
);

CREATE TABLE remotes (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    ecosystem    TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    mode         TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL
);

CREATE TABLE sync_jobs (
    id           INTEGER PRIMARY KEY,
    remote_id    INTEGER NOT NULL REFERENCES remotes (id) ON DELETE CASCADE,
    state        TEXT NOT NULL,
    interval_sec INTEGER NOT NULL DEFAULT 0,
    last_run_at  INTEGER,
    cursor       TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    object TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE TABLE object_index (
    key           TEXT PRIMARY KEY,
    etag          TEXT NOT NULL DEFAULT '',
    size          INTEGER NOT NULL DEFAULT 0,
    content_type  TEXT NOT NULL DEFAULT '',
    last_modified INTEGER,
    expires_at    INTEGER
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
