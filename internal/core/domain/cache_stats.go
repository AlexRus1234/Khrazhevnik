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

// CacheStatsRow — снапшот счётчиков статистики одной экосистемы
// (cache_stats): персистентный слепок per-eco счётчиков кеша
// (metrics.Cache), переживает рестарт процесса — кеш на диске живёт,
// а счётчики в памяти обнуляются. Снапшот-модель, не журнал: одна
// строка на экосистему, набор счётчиков всегда полный (не хвост
// дельты — флаш пишет текущие значения целиком).
type CacheStatsRow struct {
	// Ecosystem — имя экосистемы (apt, rpmmmd, …); primary key строки.
	Ecosystem string
	// Счётчики — имена и смысл те же, что у metrics.Cache.
	Hits              int64
	Misses            int64
	StaleServed       int64
	NegativeHits      int64
	UpstreamErrors    int64
	BytesFromUpstream int64
	BytesToClients    int64
	// Packages — закешированные immutable-объекты («пакеты»).
	Packages int64
	// UpdatedAt — момент снапшота; источник значения — port.Clock.
	UpdatedAt time.Time
}
