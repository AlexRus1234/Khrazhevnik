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

-- Начальная схема, диалект mariadb (docs/SPECIFICATION.md §БД). Перевод
-- sqlite-0001: INTEGER PK → BIGINT AUTO_INCREMENT, эпоха/размеры — BIGINT,
-- bool — BOOLEAN (TINYINT(1)), FK — табличные FOREIGN KEY (inline
-- REFERENCES в MySQL/MariaDB молча игнорируются). InnoDB обязателен для
-- enforcement FK. Миграционная история параллельна sqlite.

-- +goose Up
CREATE TABLE users (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    token_version BIGINT NOT NULL DEFAULT 1,
    created_at    BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE api_tokens (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id      BIGINT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT,
    last_used_at BIGINT,
    FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);

CREATE TABLE repos (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    owner_id    BIGINT NOT NULL,
    ecosystem   TEXT NOT NULL,
    quota_bytes BIGINT NOT NULL DEFAULT 0,
    quota_files BIGINT NOT NULL DEFAULT 0,
    created_at  BIGINT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE repo_perms (
    repo_id    BIGINT NOT NULL,
    user_id    BIGINT NOT NULL,
    perm       TEXT NOT NULL DEFAULT 'write',
    created_at BIGINT NOT NULL,
    PRIMARY KEY (repo_id, user_id),
    FOREIGN KEY (repo_id) REFERENCES repos (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE remotes (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    ecosystem    TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    mode         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sync_jobs (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    remote_id    BIGINT NOT NULL,
    state        TEXT NOT NULL,
    interval_sec BIGINT NOT NULL DEFAULT 0,
    last_run_at  BIGINT,
    `cursor`     TEXT NOT NULL DEFAULT '',
    updated_at   BIGINT NOT NULL,
    FOREIGN KEY (remote_id) REFERENCES remotes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_log (
    id     BIGINT AUTO_INCREMENT PRIMARY KEY,
    ts     BIGINT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    object TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE object_index (
    -- MariaDB требует длину для PK по текстовой колонке (Error 1170);
    -- postgres/sqlite держат TEXT PK без длины. 767 — безопасный предел
    -- utf8mb4 InnoDB (767*4=3068 < 3072 байт max key length).
    `key`          VARCHAR(767) NOT NULL,
    etag          TEXT NOT NULL DEFAULT '',
    size          BIGINT NOT NULL DEFAULT 0,
    content_type  TEXT NOT NULL DEFAULT '',
    last_modified BIGINT,
    expires_at    BIGINT,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- +goose Down
DROP TABLE object_index;
DROP TABLE audit_log;
DROP TABLE sync_jobs;
DROP TABLE remotes;
DROP TABLE repo_perms;
DROP TABLE repos;
DROP TABLE api_tokens;
DROP TABLE users;
