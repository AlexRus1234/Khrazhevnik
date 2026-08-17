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

// Порт HTTP-клиента: движок кеша работает с любым Doer'ом
// (*http.Client в проде, свои двойники в тестах) — таймауты,
// ретраи и прокси настраиваются снаружи, в wire.

package port

import "net/http"

// Doer — исполнитель HTTP-запросов (подмножество *http.Client).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}
