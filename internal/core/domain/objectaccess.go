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

// Scope учёта обращений (object_access): таблица общая для личных репо
// и кеш-прокси — пишем для обоих, используем (пока) для репо;
// eviction следующей волны переиспользует (решение владельца 2026-09-25).
const (
	AccessScopeRepo  = "repo"
	AccessScopeCache = "cache"
)

// ObjectAccess — последнее обращение к объекту (версии) и их число:
// давность обращения — критерий удаления ретеншна (версированный
// апстрим закрыт тем же трекингом: клиент, тянущий конкретную старую
// версию, обновляет её LastAccess). Ключ — ключ единого namespace
// хранения (repo/<id>/… для личных репо, cache/<eco>/… для кеша),
// поэтому префиксное чтение обслуживает семейства версий.
type ObjectAccess struct {
	// Scope — AccessScopeRepo или AccessScopeCache; часть первичного
	// ключа записи.
	Scope string
	// Key — ключ объекта в namespace хранения.
	Key string
	// LastAccess — момент последнего обращения; источник значения —
	// port.Clock (в БД — эпоха Unix, секунды). Мёржем не откатывается
	// назад: last_access_at = MAX(старое, новое).
	LastAccess time.Time
	// Hits — накопленное число обращений: мёрж прибавляет к старому.
	Hits int64
}
