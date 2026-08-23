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

// Int64 возвращает детерминированное число из хвоста предзагруженного
// UUID (hex → int), приведённое к [0, max). Это даёт стабильный джиттер
// в тестах планировщика без отдельного списка чисел.
func (r *fixedRand) Int64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	u := r.uuids[r.next%len(r.uuids)]
	// последние 12 hex-цифр UUID → 48-битное число; достаточно для jitter.
	var n int64
	for i := len(u) - 12; i < len(u); i++ {
		c := u[i]
		var v int64
		switch {
		case c >= '0' && c <= '9':
			v = int64(c - '0')
		case c >= 'a' && c <= 'f':
			v = int64(c-'a') + 10
		default:
			continue
		}
		n = n*16 + v
	}
	if n < 0 {
		n = -n
	}
	return n % max
}

// failingRand всегда возвращает ошибку.
type failingRand struct{ err error }

// FailingRand создаёт источник случайности, отбиваемый сбоем err.
func FailingRand(err error) port.Rand {
	return failingRand{err: err}
}

// UUID4 возвращает предзагруженную ошибку.
func (r failingRand) UUID4() (string, error) { return "", r.err }

// Int64 возвращает 0 — тесты на UUID4-сбой не гоняют Int64.
func (r failingRand) Int64(max int64) int64 { return 0 }
