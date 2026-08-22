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

package testutil

import (
	"sync"
	"testing"
	"time"
)

func TestFixedClock(t *testing.T) {
	fixed := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	c := FixedClock(fixed)
	for range 3 {
		if !c.Now().Equal(fixed) {
			t.Fatalf("FixedClock.Now() = %v, хочу %v", c.Now(), fixed)
		}
	}
}

func TestSeqClock(t *testing.T) {
	start := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	c := SeqClock(start, 30*time.Second)
	for i, want := range []time.Duration{0, 30 * time.Second, time.Minute, 90 * time.Second} {
		if got := c.Now(); !got.Equal(start.Add(want)) {
			t.Fatalf("шаг %d: Now() = %v, хочу %v", i, got, start.Add(want))
		}
	}
}

func TestSeqClockDefaultStep(t *testing.T) {
	start := time.Unix(0, 0)
	// Неположительный шаг заменяется секундой — защита от вечного
	// «одного и того же момента» в тестах, ожидавших движение.
	c := SeqClock(start, 0)
	first, second := c.Now(), c.Now()
	if second.Sub(first) != time.Second {
		t.Fatalf("шаг по умолчанию = %v, хочу 1s", second.Sub(first))
	}
}

func TestSeqClockConcurrent(t *testing.T) {
	c := SeqClock(time.Unix(0, 0), time.Nanosecond)
	var wg sync.WaitGroup
	seen := make(chan time.Time, 64)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				seen <- c.Now()
			}
		}()
	}
	wg.Wait()
	close(seen)
	uniq := map[time.Time]bool{}
	for ts := range seen {
		if uniq[ts] {
			t.Fatalf("дубль метки времени %v: SeqClock обязан быть строго монотонным", ts)
		}
		uniq[ts] = true
	}
}

func TestManualClock(t *testing.T) {
	start := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	c := NewManualClock(start)
	if !c.Now().Equal(start) {
		t.Fatalf("Now() = %v, хочу %v", c.Now(), start)
	}
	if got := c.Advance(90 * time.Second); !got.Equal(start.Add(90 * time.Second)) {
		t.Fatalf("Advance = %v, хочу %v", got, start.Add(90*time.Second))
	}
	if !c.Now().Equal(start.Add(90 * time.Second)) {
		t.Fatalf("Now() после Advance = %v", c.Now())
	}
}
