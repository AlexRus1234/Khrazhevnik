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

// Хендлер справочника экосистем сборки (/api/v1/ecosystems, сессия 178).
// Тонкий: ключи карты адаптеров из Deps (их собирает wire из реестра) →
// отсортированный массив имён. Список отдаёт бекенд, а не фронтенд:
// UI-дропдаун не может отстать от реестра (класс бага «дописали
// экосистему в бекенде — забыли в web-массиве» умирает).

package web

import (
	"net/http"
	"slices"
)

// ecosystemsOut — тело GET /ecosystems: имена доступных экосистем
// (включённых в сборке) в лексическом порядке.
type ecosystemsOut struct {
	Ecosystems []string `json:"ecosystems"`
}

// handleListEcosystems — GET /api/v1/ecosystems: 200
// {"ecosystems":["apk","apt",…]}. Источник — ключи Deps.Ecosystems
// (router.go:49): карта собирается wire'ом из реестра, выключенных
// конфигом экосистем в ней нет, поэтому ответ честно значит «доступные».
// Чтение без аудита (auditWrap пишет только мутации; прецедент GET /repos).
func handleListEcosystems(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		names := make([]string, 0, len(d.Ecosystems))
		for name := range d.Ecosystems {
			names = append(names, name)
		}
		slices.Sort(names)
		writeJSON(w, http.StatusOK, ecosystemsOut{Ecosystems: names})
	}
}
