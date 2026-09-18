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

package xbps

import (
	"errors"
	"testing"

	"khrazhevnik/internal/core/domain"
)

// FuzzSplitPkgver: парсер чужого формата не паникует на произвольном
// вводе; успешный разбор roundtrip-инвариантен и режет по последней
// границе имя/версия; любой отказ — типизированный ValidationError.
func FuzzSplitPkgver(f *testing.F) {
	seeds := []string{
		"0ad-0.27.1_6",
		"python3-pip-24.0_1",
		"libstdc++-13.2.0_1",
		"Mustache-4.1_1",
		"66-init-0.8.2.2_1",
		"foo-2~beta1_2",
		"xtools-0.59_1",
		"foo-1.0",
		"foo-1.0_",
		"foo-1.0_x",
		"",
		"nodash",
		"-1.0_1",
		"foo-bar",
		"foo-1-bar",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		name, version, err := SplitPkgver(in)
		if err != nil {
			var ve *domain.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("SplitPkgver(%q) вернул %T (%v), ожидался *domain.ValidationError", in, err, err)
			}
			return
		}
		if name == "" {
			t.Fatalf("SplitPkgver(%q) вернул пустое имя без ошибки", in)
		}
		if name+"-"+version != in {
			t.Fatalf("roundtrip нарушен: (%q, %q) для %q", name, version, in)
		}
		if !isDigit(version[0]) {
			t.Fatalf("SplitPkgver(%q) вернул версию %q не с цифры", in, version)
		}
		if idx := splitIndex(in); idx != len(name) {
			t.Fatalf("SplitPkgver(%q) порезал не по последней границе: idx=%d, имя=%q", in, idx, name)
		}
	})
}
