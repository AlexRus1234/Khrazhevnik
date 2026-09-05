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

-- FK api_tokens.user_id → ON DELETE CASCADE (сессия 79): пользователь
-- с API-токенами удалялся FK-нарушением (409 вместо 204) — выданный
-- токен делал владельца неудаляемым через API. В sqlite FK нельзя
-- ALTER — честный table-rebuild (copy-drop-rename); goose оборачивает
-- миграцию в транзакцию, у таблицы нет дочерних FK — разрыва ссылок
-- нет. Состав колонок = 0001 + revoked_at (0002).

-- +goose Up
CREATE TABLE api_tokens_new (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
INSERT INTO api_tokens_new (id, user_id, name, prefix, token_hash, scopes, created_at, expires_at, last_used_at, revoked_at)
    SELECT id, user_id, name, prefix, token_hash, scopes, created_at, expires_at, last_used_at, revoked_at FROM api_tokens;
DROP TABLE api_tokens;
ALTER TABLE api_tokens_new RENAME TO api_tokens;
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);

-- +goose Down
ALTER TABLE api_tokens RENAME TO api_tokens_old;
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id),
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
INSERT INTO api_tokens (id, user_id, name, prefix, token_hash, scopes, created_at, expires_at, last_used_at, revoked_at)
    SELECT id, user_id, name, prefix, token_hash, scopes, created_at, expires_at, last_used_at, revoked_at FROM api_tokens_old;
DROP TABLE api_tokens_old;
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);


