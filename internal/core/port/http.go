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

import (
	"context"
	"net/http"
)

// Doer — исполнитель HTTP-запросов (подмножество *http.Client).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewGETRequest keeps HTTP construction at the delivery port boundary so
// usecase packages do not depend on net/http directly.
func NewGETRequest(ctx context.Context, url string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Явный identity (история L9, сессия 69): DisableCompression лишь
	// не добавляет Accept-Encoding сам — некомплаентный upstream/CDN
	// может сжать ответ вопреки; gzip лёг бы в кеш byte-exact без
	// Content-Encoding в ObjectMeta и ушёл бы клиенту мусором.
	// Проксирование Content-Encoding upstream'а — пост-v1 (схема).
	req.Header.Set("Accept-Encoding", "identity")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return req, nil
}
