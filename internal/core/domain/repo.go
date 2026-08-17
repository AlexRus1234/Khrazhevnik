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

// Quota — лимиты личного репозитория; нулевое поле = без лимита.
type Quota struct {
	MaxBytes   int64
	MaxObjects int64
}

// Repo — личный репозиторий пользователя. Ecosystem — имя адаптера
// («apt», «rpm-md», ...); схема хранения: repo/<repo-id>/...
type Repo struct {
	ID        int64
	OwnerID   int64
	Name      string
	Ecosystem string
	Quota     Quota
	CreatedAt time.Time
}

// Perm — право записи в личный репозиторий. Чтение публичное, поэтому
// права только на запись.
type Perm struct {
	RepoID    int64
	UserID    int64
	CreatedAt time.Time
}
