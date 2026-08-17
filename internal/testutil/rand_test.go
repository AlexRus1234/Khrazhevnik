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
	"errors"
	"testing"
)

func TestFixedRand(t *testing.T) {
	r := FixedRand("aaa", "bbb")
	for _, want := range []string{"aaa", "bbb", "aaa", "bbb"} {
		got, err := r.UUID4()
		if err != nil || got != want {
			t.Fatalf("UUID4() = %q, %v; хочу %q", got, err, want)
		}
	}
}

func TestFixedRandDefault(t *testing.T) {
	r := FixedRand()
	got, err := r.UUID4()
	if err != nil || got != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("UUID4() по умолчанию = %q, %v", got, err)
	}
}

func TestFailingRand(t *testing.T) {
	boom := errors.New("boom")
	r := FailingRand(boom)
	got, err := r.UUID4()
	if !errors.Is(err, boom) || got != "" {
		t.Fatalf("UUID4() = %q, %v; хочу ошибку boom", got, err)
	}
}
