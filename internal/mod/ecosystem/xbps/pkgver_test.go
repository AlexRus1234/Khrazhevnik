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

// TestSplitPkgver — живой зоопарк имён Void (урок 65: реальные имена, не
// «foo»): дефисы, `++`, ведущие цифры, `~` в версии, заглавные буквы.
func TestSplitPkgver(t *testing.T) {
	cases := []struct {
		in      string
		name    string
		version string
	}{
		{"0ad-0.27.1_6", "0ad", "0.27.1_6"},
		{"python3-pip-24.0_1", "python3-pip", "24.0_1"},
		{"libstdc++-13.2.0_1", "libstdc++", "13.2.0_1"},
		{"Mustache-4.1_1", "Mustache", "4.1_1"},
		{"66-init-0.8.2.2_1", "66-init", "0.8.2.2_1"},
		{"foo-2~beta1_2", "foo", "2~beta1_2"},
		{"xtools-0.59_1", "xtools", "0.59_1"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			name, version, err := SplitPkgver(tc.in)
			if err != nil {
				t.Fatalf("SplitPkgver(%q) = ошибка %v, ожидалось без ошибки", tc.in, err)
			}
			if name != tc.name || version != tc.version {
				t.Fatalf("SplitPkgver(%q) = (%q, %q), ожидалось (%q, %q)",
					tc.in, name, version, tc.name, tc.version)
			}
			if name+"-"+version != tc.in {
				t.Fatalf("инвариант roundtrip нарушен: %q + %q + %q != %q",
					name, "-", version, tc.in)
			}
		})
	}
}

// TestSplitPkgverInvalid — мусор не паникует и не проходит; типизированно
// ValidationError (контракт, не текст: правило 17).
func TestSplitPkgverInvalid(t *testing.T) {
	cases := []string{
		"",          // пустая строка
		"nodash",    // нет границы имя/версия
		"-1.0_1",    // пустое имя
		"foo-bar",   // после дефиса не цифра
		"foo-1.0_",  // ревизия после «_» пуста
		"foo-1.0_x", // ревизия не из цифр
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			name, version, err := SplitPkgver(in)
			if err == nil {
				t.Fatalf("SplitPkgver(%q) = (%q, %q), ожидалась ошибка", in, name, version)
			}
			var ve *domain.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("SplitPkgver(%q) вернул %T, ожидался *domain.ValidationError", in, err)
			}
			if ve.What != "pkgver" {
				t.Fatalf("What = %q, ожидалось %q", ve.What, "pkgver")
			}
		})
	}
}

// TestSplitRevision — суффикс `_N` (цифры); отсутствие/нецифровой хвост
// не ошибка, а ok=false с нетронутой upstream-частью.
func TestSplitRevision(t *testing.T) {
	cases := []struct {
		in       string
		upstream string
		revision string
		ok       bool
	}{
		{"0.27.1_6", "0.27.1", "6", true},
		{"13.2.0_1", "13.2.0", "1", true},
		{"1.0_0", "1.0", "0", true},
		{"2~beta1_2", "2~beta1", "2", true},
		{"1.0", "1.0", "", false},
		{"1.0_", "1.0_", "", false},
		{"1.0_x", "1.0_x", "", false},
		{"1.0_1x", "1.0_1x", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			upstream, revision, ok := SplitRevision(tc.in)
			if upstream != tc.upstream || revision != tc.revision || ok != tc.ok {
				t.Fatalf("SplitRevision(%q) = (%q, %q, %v), ожидалось (%q, %q, %v)",
					tc.in, upstream, revision, ok, tc.upstream, tc.revision, tc.ok)
			}
		})
	}
}

// TestFilename — формула клиента libxbps (transaction_fetch.c):
// <pkgver>.<arch>.xbps.
func TestFilename(t *testing.T) {
	if got, want := Filename("0ad-0.27.1_6", "x86_64"), "0ad-0.27.1_6.x86_64.xbps"; got != want {
		t.Fatalf("Filename = %q, ожидалось %q", got, want)
	}
	if got, want := Filename("libstdc++-13.2.0_1", "aarch64"), "libstdc++-13.2.0_1.aarch64.xbps"; got != want {
		t.Fatalf("Filename = %q, ожидалось %q", got, want)
	}
}
