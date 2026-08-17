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

// Двойники port.Rand: FixedRand раздаёт предзагруженные UUID по кругу,
// FailingRand отбивает сбоем (проверка обработок ошибок в engine).

package testutil

import "khrazhevnik/internal/core/port"

// fixedRand циклически раздаёт предзагруженные UUID; при пустом
// списке — нулевой UUID v4.
type fixedRand struct {
	uuids []string
	next  int
}

// FixedRand создаёт источник, возвращающий uuids по очереди; после
// исчерпания списка — снова с начала.
func FixedRand(uuids ...string) port.Rand {
	if len(uuids) == 0 {
		uuids = []string{"00000000-0000-4000-8000-000000000000"}
	}
	return &fixedRand{uuids: uuids}
}

// UUID4 возвращает очередной предзагруженный UUID.
func (r *fixedRand) UUID4() (string, error) {
	u := r.uuids[r.next%len(r.uuids)]
	r.next++
	return u, nil
}

// failingRand всегда возвращает ошибку.
type failingRand struct{ err error }

// FailingRand создаёт источник случайности, отбиваемый сбоем err.
func FailingRand(err error) port.Rand {
	return failingRand{err: err}
}

// UUID4 возвращает предзагруженную ошибку.
func (r failingRand) UUID4() (string, error) { return "", r.err }
