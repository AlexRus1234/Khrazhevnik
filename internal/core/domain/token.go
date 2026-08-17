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

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Scope — право API-токена: либо полный административный доступ,
// либо запись в конкретный личный репозиторий.
type Scope string

// ScopeAdmin — токен с полным доступом (эквивалент роли admin).
const ScopeAdmin Scope = "admin"

// APIToken — scoped API-токен. Токен целиком показывается один раз
// при создании; хранится только SHA256 (hex) и короткий префикс для
// узнавания в списке.
type APIToken struct {
	ID        int64
	UserID    int64
	Name      string
	Prefix    string // первые символы токена для отображения
	SHA256    string // hex(sha256(токен)) — единственная хранимая форма
	Scopes    []Scope
	CreatedAt time.Time
	// ExpiresAt нулевой — бессрочный токен.
	ExpiresAt time.Time
}

// HashToken — единая точка хеширования токенов: sha256 в hex.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// AllowsWrite сообщает, даёт ли scope право записи в репозиторий
// repoID: admin — да; repo:<id>:write — только свой id.
func (s Scope) AllowsWrite(repoID int64) bool {
	if s == ScopeAdmin {
		return true
	}
	return s == Scope(fmt.Sprintf("repo:%d:write", repoID))
}
