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

package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// chiURLParam — тонкая обёртка, чтобы validate.go не импортировал chi
// (только ради одной функции). Сборка хендлеров идёт через chi-роутер,
// так что параметр всегда достаётся из контекста запроса.
func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}
