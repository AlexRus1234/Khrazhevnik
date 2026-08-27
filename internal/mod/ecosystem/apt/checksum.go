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

// checksumIndex — знания адаптера о чексуммах объектов remote,
// извлечённые из индекса экосистемы при Enumerate (sync зеркала).
// Прокси-запросы через Resolve подтягивают их в port.Target.Checksum;
// если sync ещё не гонялся, чексумм нет — движок кеша честно деградирует
// к сверке Content-Length. Дубликат из apk/rpmmmd: mod→mod запрещён,
// адаптеры самодостаточны.

package apt

import (
	"strings"
	"sync"

	"khrazhevnik/internal/core/port"
)

// checksumIndex — потокобезопасная таблица «remote-id → upstream-путь →
// чексумма». Запись — полная замена по remote: Enumerate перечитывает
// индекс целиком, прежние знания устаревать не должны.
type checksumIndex struct {
	mu   sync.RWMutex
	byID map[int64]map[string]port.Checksum
}

// newChecksumIndex создаёт пустую таблицу.
func newChecksumIndex() *checksumIndex {
	return &checksumIndex{byID: map[int64]map[string]port.Checksum{}}
}

// replace целиком заменяет знания о remote id.
func (c *checksumIndex) replace(id int64, sums map[string]port.Checksum) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byID[id] = sums
}

// lookup возвращает чексумму upstream-пути (с ведущим «/») remote.
func (c *checksumIndex) lookup(id int64, upstreamPath string) (port.Checksum, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sums, ok := c.byID[id]
	if !ok {
		return port.Checksum{}, false
	}
	sum, ok := sums[upstreamPath]
	return sum, ok
}

// hexChecksum валидирует пару «алгоритм/hex» из индекса: мусорный hex
// не должен превращаться в вечный checksum mismatch у каждого запроса.
// Не-hex или пустое значение — «чексуммы нет» (честная деградация).
func hexChecksum(algo, hex string) (port.Checksum, bool) {
	hex = strings.ToLower(strings.TrimSpace(hex))
	if hex == "" {
		return port.Checksum{}, false
	}
	for i := 0; i < len(hex); i++ {
		b := hex[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return port.Checksum{}, false
		}
	}
	return port.Checksum{Algo: algo, Hex: hex}, true
}
