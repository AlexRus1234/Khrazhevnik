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

-- FK api_tokens.user_id → ON DELETE CASCADE (сессия 79), диалект
-- postgres: без каскада пользователь с API-токенами неудаляем
-- (FK-нарушение → 409 вместо 204). Имя inline-констрейнта 0001 —
-- автогенерат <таблица>_<колонка>_fkey, предсказуемо.

-- +goose Up
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_user_id_fkey;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_user_id_fkey;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users (id);
