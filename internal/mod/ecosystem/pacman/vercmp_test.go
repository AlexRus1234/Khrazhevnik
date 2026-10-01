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

package pacman

import "testing"

// TestComparePkgVer — таблица знаков (<0/0/>0): контракт компаратора —
// порядок версий (им выбирается запись .db при дедупе), а не конкретное
// возвращаемое число.
func TestComparePkgVer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want int
	}{
		// epoch имеет приоритет над цифрами версии; epoch по умолчанию 0.
		{"1:1.0.0-1", "2.0.0-1", 1},
		{"2.0.0-1", "1:1.0.0-1", -1},
		{"1:1.0-1", "0:2.0-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		// release (pkgrel) сравнивается после версии.
		{"7.0.0-2", "7.0.0-1", 1},
		{"7.0.0-1", "7.0.0-2", -1},
		{"1.0-1.1", "1.0-1", 1},
		{"1.0-1", "1.0-1.1", -1},
		// Числовые сегменты — числом, не лексически.
		{"1.0.1", "1.0.0", 1},
		{"1.2", "1.10", -1},
		{"1.10", "1.2", 1},
		// Алфавитный хвост младше релиза (libalpm: хвост vs пустое).
		{"1.0alpha1", "1.0", -1},
		{"1.0", "1.0alpha1", 1},
		{"1.0rc1", "1.0", -1},
		{"1.0beta", "1.0alpha", 1},
		// Длина разделителей влияет на исход (libalpm, до сегментов).
		{"1.0", "1..0", -1},
		// Равные.
		{"1.0-1", "1.0-1", 0},
		{"1:1.0.0-3", "1:1.0.0-3", 0},
		{"7.0.0-1", "7.0.0-1", 0},
		// release у одного отсутствует — для alpm версии эквивалентны.
		{"1.0", "1.0-1", 0},
		{"1.0-1", "1.0", 0},
		// Пустые — детерминированный порядок, не паника.
		{"", "", 0},
		{"", "1.0-1", -1},
		{"1.0-1", "", 1},
		// Живой дефект волны: lxc-loc-7.0.0-1 против lxc-loc-7.0.0-2.
		{"7.0.0-2", "7.0.0-1", 1},
	}
	for _, c := range cases {
		got := signOf(ComparePkgVer(c.a, c.b))
		if got != c.want {
			t.Errorf("ComparePkgVer(%q, %q) = %d, хочу знак %d", c.a, c.b, got, c.want)
		}
		// Антисимметрия — тот же контракт с другой стороны.
		if rev := signOf(ComparePkgVer(c.b, c.a)); rev != -c.want {
			t.Errorf("ComparePkgVer(%q, %q) = %d, антисимметрия нарушена", c.b, c.a, rev)
		}
	}
}

// signOf сводит значение компаратора к -1/0/1: контракт — знак.
func signOf(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// TestComparePkgVerDeterministicOnGarbage — пустые и некорректные
// версии не паникуют и дают устойчивый знак: компаратор сравнивает, а
// не валидирует, но выбор записи при дедупе обязан быть
// детерминированным при любом входе.
func TestComparePkgVerDeterministicOnGarbage(t *testing.T) {
	t.Parallel()
	odd := []string{"", "-", "-1.0", ":", "1:", "not-a-version", "1..0", "1.0-", "1.0--1", "00", "1:1:2-3"}
	for _, a := range odd {
		for _, b := range odd {
			first, second := ComparePkgVer(a, b), ComparePkgVer(a, b)
			if signOf(first) != signOf(second) {
				t.Fatalf("ComparePkgVer(%q, %q) недетерминирован: %d ≠ %d", a, b, first, second)
			}
			if rev := signOf(ComparePkgVer(b, a)); rev != -signOf(first) {
				t.Errorf("антисимметрия на (%q, %q): %d против %d", a, b, first, rev)
			}
		}
	}
}
