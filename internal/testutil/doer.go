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

// Тестовый DoerFactory: один Doer на любую прокси-строку — поведение
// движка до per-target выбора (сессии 150–151).

package testutil

import "khrazhevnik/internal/core/port"

// StaticDoerFactory оборачивает Doer в port.DoerFactory.
type StaticDoerFactory struct{ Doer port.Doer }

// DoerFor отдаёт единственный Doer, прокси-строку игнорирует.
func (f StaticDoerFactory) DoerFor(string) port.Doer { return f.Doer }
