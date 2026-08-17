// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package domain

import "time"

// Role — роль пользователя админки. Роль берётся из БД на каждом
// запросе (паранойя: claim'ам JWT не доверяем).
type Role string

// Роли: admin управляет всем, user — только личными репозиториями.
const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User — учётная запись админки. PasswordHash — bcrypt; сам пароль
// нигде не хранится.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         Role
	// TokenVersion инвалидирует все JWT-сессии пользователя при
	// смене пароля/роли: значение сверяется с БД на каждом запросе.
	TokenVersion int64
	CreatedAt    time.Time
}
