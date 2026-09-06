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
	"net/url"

	"github.com/go-chi/chi/v5"
)

// chiURLParam — тонкая обёртка, чтобы validate.go не импортировал chi
// (только ради одной функции). Сборка хендлеров идёт через chi-роутер,
// так что параметр всегда достаётся из контекста запроса.
func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

// decodedWildcard — chi v5.3.1 маршрутизирует по RawPath (mux.go:455):
// клиент, кодирующий «+» как %2b (apt на libnl-3/g++), оставляет
// wildcard экранированным, и ключ с «%» отсекается whitelist'ом
// ValidateKey — 400 на валидном upstream-пути (CI-факт №4). Декод
// ДО ValidateKey сохраняет инварианты: %25/%2e%2e fail-closed ниже.
// PathUnescape сырое «+» не трогает (это не QueryUnescape). Когда
// RawPath пуст, chi маршрутизировал по Path — параметр уже декодирован,
// и повторный unescape алиасил бы двойное кодирование (%252b → %2b →
// «+» в чужой объект) вместо fail-closed 400 на «%». Ветка ошибки
// — defensive: net/http сам не пропускает битые escape.
func decodedWildcard(r *http.Request) (string, error) {
	tail := chi.URLParam(r, "*")
	if r.URL.RawPath == "" {
		return tail, nil
	}
	return url.PathUnescape(tail)
}
