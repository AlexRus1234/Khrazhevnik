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

// Двойники port.Clock: FixedClock замирает на одном моменте, SeqClock
// идёт вперёд с шагом — строго возрастающие метки без гонок с
// реальным временем.

package testutil

import (
	"sync"
	"time"

	"khrazhevnik/internal/core/port"
)

// fixedClock всегда возвращает один и тот же момент.
type fixedClock struct{ t time.Time }

// FixedClock создаёт часы, замороженные на t.
func FixedClock(t time.Time) port.Clock {
	return fixedClock{t: t}
}

// Now возвращает зафиксированное время.
func (c fixedClock) Now() time.Time { return c.t }

// seqClock раздаёт время с постоянным шагом; потокобезопасна.
type seqClock struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

// SeqClock создаёт часы, идущие вперёд на step за каждый вызов Now.
// Неположительный step заменяется на секунду.
func SeqClock(start time.Time, step time.Duration) port.Clock {
	if step <= 0 {
		step = time.Second
	}
	return &seqClock{next: start, step: step}
}

// Now возвращает очередное значение и сдвигает часы на шаг.
func (c *seqClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.next
	c.next = c.next.Add(c.step)
	return t
}
