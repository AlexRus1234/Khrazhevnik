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
// извлечённые из APKINDEX при Enumerate (sync зеркала). Прокси-запросы
// через Resolve подтягивают их в port.Target.Checksum; если sync ещё не
// гонялся, чексумм нет — движок кеша честно деградирует к сверке
// Content-Length. Дубликат из apt/rpmmmd: mod→mod запрещён, адаптеры
// самодостаточны.

package apk

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"khrazhevnik/internal/core/port"
)

// checksumIndex — потокобезопасная таблица «remote-id → upstream-путь →
// чексумма». Запись — полная замена по remote: Enumerate перечитывает
// APKINDEX целиком, прежние знания устаревать не должны.
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

// csumFromIndex декодирует поле C: APKINDEX в чексумму пакета. Формат
// apk-tools: «Q» + цифра алгоритма + base64(raw digest); «Q1» — SHA1
// (единственный алгоритм APKINDEX v2). Не-«Q1» или кривой base64 —
// «чексуммы нет»: деградация к Content-Length лучше ложного mismatch.
func csumFromIndex(val string) (port.Checksum, bool) {
	raw, ok := strings.CutPrefix(val, "Q1")
	if !ok {
		return port.Checksum{}, false
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Часть apk-сборщиков пишет без паддинга и/или url-safe алфавит.
		data, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(raw)
	}
	if err != nil || len(data) != sha1.Size {
		return port.Checksum{}, false
	}
	return port.Checksum{Algo: "sha1", Hex: fmt.Sprintf("%x", data)}, true
}
