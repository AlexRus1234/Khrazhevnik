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
	"strings"
	"testing"
)

// deweyCases — таблица знаков компаратора. Контракт — знак (<0/0/>0), а не
// конкретное число: им генератор выбирает запись, остающуюся в index.plist.
//
// Ожидания НЕ выведены рассуждением, а сняты с живого клиента: каждая пара
// прогнана через `xbps-uhelper cmpver` (XBPS 0.59.1, образ
// voidlinux/voidlinux), знак = код возврата (0/1/-1). Первые восемь пар —
// официальная таблица самого xbps (tests/xbps/libxbps/cmpver/main.c),
// остальные добавлены под наши случаи (ревизия, `~`, регистр, ревизия 0,
// реальный случай пробы `lxc-loc`).
var deweyCases = []struct {
	a, b string
	want int
}{
	// Официальная таблица xbps.
	{"foo-1.0", "foo-1.0", 0},
	{"foo-1.0", "foo-1.0_1", -1},
	{"foo-1.0_1", "foo-1.0", 1},
	{"foo-2.0rc2", "foo-2.0rc3", -1},
	{"foo-129", "foo-129_1", -1},
	{"foo-blah-100dpi-21", "foo-blah-100dpi-21_0", 0},
	{"foo-blah-100dpi-21", "foo-blah-100dpi-2.1", 1},
	{"foo-1.0.1", "foo-1.0_1", 1},
	// Ревизия: после версии; `_0` и отсутствие ревизии эквивалентны.
	{"foo-1.0_1", "foo-1.0_2", -1},
	{"foo-7.0.0_1", "foo-7.0.0_2", -1},
	{"foo-7.5.1_1", "foo-7.5.1_2", -1},
	{"foo-1.0_0", "foo-1.0", 0},
	{"foo-1.0", "foo-1.0_0", 0},
	{"foo-1.0.0_1", "foo-1.0.10_1", -1},
	{"foo-1.0.0_1", "foo-1.0_1", 0},
	{"foo-2.0_1", "foo-2.0.0_1", 0},
	{"foo-1.0_2", "foo-1.0.0_2", 0},
	// Числовые компоненты — числом, не лексически.
	{"foo-1.0.0", "foo-1.0.10", -1},
	{"foo-1.2", "foo-1.10", -1},
	{"foo-1.10", "foo-1.2", 1},
	{"foo-0.1", "foo-0.10", -1},
	{"foo-10", "foo-9", 1},
	{"foo-1.01", "foo-1.1", 0},
	{"foo-24.2_1", "foo-24.2_10", -1},
	{"foo-1.0.0.1", "foo-1.0.0.2", -1},
	// Хвостовые нули не значимы (недостающий компонент — ноль).
	{"foo-1.0", "foo-1.0.0", 0},
	{"foo-1.0", "foo-1.0.0.0", 0},
	{"foo-3.0", "foo-3", 0},
	{"foo-2.0", "foo-2.0.0", 0},
	{"foo-2.0.0", "foo-2.0", 0},
	// Модификаторы: alpha < beta < pre == rc < версия; pl == `.`.
	{"foo-1.0alpha1", "foo-1.0", -1},
	{"foo-1.0beta", "foo-1.0alpha", 1},
	{"foo-1.0pre1", "foo-1.0rc1", 0},
	{"foo-1.0pl1", "foo-1.0", 1},
	{"foo-1.0", "foo-1.0rc1", 1},
	// `~` отдельной семантики не имеет: это пропускаемый байт.
	{"foo-1.0~rc1", "foo-1.0", -1},
	{"foo-1.0~rc1", "foo-1.0~rc2", -1},
	// Буква — компонент (Dot + номер буквы): «1.0a» младше «1.0b».
	{"foo-1.0", "foo-1.0a", -1},
	{"foo-1.0a", "foo-1.0b", -1},
	// Регистр имён и буквенных компонентов значимости не имеет.
	{"Mustache-4.1_1", "Mustache-4.1_2", -1},
	{"foo-1.0A", "foo-1.0b", -1},
	// Случай живой пробы: 7.0.10 новее 7.0.9, хотя лексически ключ
	// `7.0.10_1` идёт раньше `7.0.9_1` (и клиент без дедупа взял старую).
	{"lxc-loc-7.0.10_1", "lxc-loc-7.0.9_1", 1},
	{"lxc-loc-7.0.9_1", "lxc-loc-7.0.10_1", -1},
	// Равные.
	{"foo-1.0_1", "foo-1.0_1", 0},
	{"xtools-0.59_1", "xtools-0.59_1", 0},
	// Имена сравниваются байтово (у дедупа имена совпадают всегда).
	{"bar-1.0", "foo-1.0", -1},
	{"foo-1.0", "bar-1.0", 1},
	// Пустые и мусор — детерминированный порядок, не паника.
	{"", "", 0},
	{"", "foo-1.0", -1},
	{"foo-", "foo-1.0", -1},
}

// TestCompareXbpsVer — таблица deweyCases против нашего порта.
func TestCompareXbpsVer(t *testing.T) {
	t.Parallel()
	for _, tc := range deweyCases {
		if got := CompareXbpsVer(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareXbpsVer(%q, %q) = %d, хотим %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestCompareXbpsVerAntisymmetry — знак обязан быть антисимметричным:
// дедуп опирается на одну и ту же функцию с обеих сторон сравнения.
func TestCompareXbpsVerAntisymmetry(t *testing.T) {
	t.Parallel()
	for _, tc := range deweyCases {
		got := CompareXbpsVer(tc.b, tc.a)
		if got != -tc.want {
			t.Errorf("CompareXbpsVer(%q, %q) = %d, хотим %d (обратный знак)", tc.b, tc.a, got, -tc.want)
		}
	}
}

// TestCompareXbpsVerGarbageDeterministic — мусорный вход (обрубки pkgver,
// длинные прогоны цифр, UTF-8, не-ASCII байты) не роняет компаратор и даёт
// детерминированный знак: выбор записи при дедупе не должен зависеть от
// порядка вызовов (образец pacman.TestComparePkgVerDeterministicOnGarbage).
func TestCompareXbpsVerGarbageDeterministic(t *testing.T) {
	t.Parallel()
	garbage := []string{
		"", "-", "_", "_1", "....", "----", "foo", "foo-", "foo-_", "foo-_1",
		"foo-1.0_", "foo-1.0__1", "foo-1.0-mu", "1e999999999999999999999999",
		"foo-000000000000000000001", "foo-99999999999999999999999999999999",
		"ё-1.0", "foo-1.0\x00", strings.Repeat("9", 64), strings.Repeat("a-", 8) + "1",
	}
	for _, a := range garbage {
		for _, b := range garbage {
			ab := CompareXbpsVer(a, b)
			if ab != CompareXbpsVer(a, b) {
				t.Fatalf("CompareXbpsVer(%q, %q) не детерминирован", a, b)
			}
			if ba := CompareXbpsVer(b, a); ba != -ab {
				t.Fatalf("CompareXbpsVer(%q, %q) = %d, обратное = %d — не антисимметрично", a, b, ab, ba)
			}
			if a == b && ab != 0 {
				t.Fatalf("CompareXbpsVer(%q, %q) = %d, хотим 0", a, b, ab)
			}
		}
	}
}

// TestCompareXbpsVerOverflowParity — длинные прогоны цифр переполняют `int` в
// dewey.c, причём дважды: при накоплении числа (n = n*10 + d) и при вычитании
// компонентов (DIGIT(lhs) - DIGIT(rhs)). Клиент сравнивает уже переполненные
// значения, и мы повторяем это поведение — иначе в index.plist осталась бы не
// та версия. Все знаки сняты с живого `xbps-uhelper cmpver` (файлы num.tsv и
// num2.tsv), включая края INT32_MIN/INT32_MAX. Таблица заодно фиксирует, что
// переполнение не превращается в панику.
func TestCompareXbpsVerOverflowParity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want int
	}{
		// Накопление: значения за 2^31 заворачиваются.
		{"xtools-2400127517_3", "xtools-143b31", -1},
		{"xtools-28z", "xtools-31132230023_3", -1},
		{"xtools-153227001_4", "xtools-1000100126_0", -1},
		{"xtools-1237b.29_0", "xtools-1135233820_3", -1},
		{"xtools-254028401111", "xtools-342.29Q32_1", 1},
		{"xtools-8_2A020118_3", "xtools-19000001232_1", -1},
		// Накопление по модулю: 4294967297 ≡ 1 (mod 2^32) — «равно» единице.
		{"foo-4294967296", "foo-1", -1},
		{"foo-4294967297", "foo-1", 0},
		{"foo-4294967295", "foo-1", -1},
		{"foo-99999999999", "foo-1", 1},
		{"foo-0000000000000000000000001", "foo-1", 0},
		// Вычитание: INT32_MIN - 1 заворачивается в положительное, поэтому
		// `foo-2147483648` для клиента БОЛЬШЕ единицы и больше INT32_MAX.
		{"foo-2147483647", "foo-1", 1},
		{"foo-2147483648", "foo-1", 1},
		{"foo-2147483649", "foo-1", -1},
		{"foo-2147483648", "foo-2147483647", 1},
		{"foo-1.2147483648", "foo-1.0", -1},
		{"foo-0", "foo-2147483648", -1},
		{"foo-2147483648", "foo-2147483648", 0},
		{"foo-2147483648", "foo-2147483649", -1},
		{"foo-2147483648_1", "foo-1.2147483648", 1},
		// Ревизия сравнивается тем же вычитанием.
		{"foo-1_2147483648", "foo-1_1", 1},
		{"foo-1_2147483649", "foo-1_1", -1},
		// Прогоны в пределах int32 сравниваются как обычно.
		{"xtools-153227001_4", "xtools-153227002_4", -1},
	}
	for _, tc := range cases {
		if got := CompareXbpsVer(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareXbpsVer(%q, %q) = %d, хотим %d", tc.a, tc.b, got, tc.want)
		}
	}
}
