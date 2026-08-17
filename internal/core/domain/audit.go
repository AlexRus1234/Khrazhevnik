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

// Результаты записей аудита.
const (
	AuditOK    = "ok"
	AuditError = "error"
)

// AuditEntry — запись аудита о мутации: кто, что сделал, над чем,
// чем кончилось. Пишется движком после каждой мутации, чтение —
// с пагинацией по возрастанию ID.
type AuditEntry struct {
	ID     int64
	At     time.Time
	Actor  string // username или «system»
	Action string // «user.create», «repo.delete», ...
	Object string // «user:alice», «repo:42», ...
	Result string // AuditOK | AuditError
	Detail string
}
