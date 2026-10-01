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

// Сравнение версий xbps-пакетов по семантике libxbps (xbps_cmpver →
// dewey_cmp, lib/external/dewey.c). Нужно генератору личного репо:
// index.plist — словарь pkgname → поля, ключ обязан быть один, и версию
// выбирает ГЕНЕРАТОР — сам клиент записи не выбирает, дубль ключа в
// словаре он молча схлопывает, оставляя ПОСЛЕДНЮЮ по XML запись, а порядок
// записей задаёт лексический порядок ключей storage, а не порядок версий
// (живая проба 2026-10-01: из `7.0.10_1` и `7.0.9_1` клиент видел
// `7.0.9_1` — СТАРУЮ). Значит порядок компаратора обязан совпадать с
// клиентским (в xbps это `xbps_cmpver`; имя `xbps_pkgversion_cmp` из
// планировочного текста сессии — тот же алгоритм), иначе в индексе
// останется не та версия.
//
// Алгоритм — порт dewey (NetBSD-версия, как она поставляется в xbps):
// строка версии режется на компоненты, цифровой прогон — число;
// модификаторы `alpha`/`beta`/`pre`/`rc`/`pl`/`.` — коды -3/-2/-1/-1/0/0
// (регистр не важен, совпадение по префиксу); `_` — ревизия, участвует в
// сравнении последней; прочая латинская буква — ноль (Dot) плюс её номер в
// алфавите; ЛЮБОЙ другой байт (`~`, `-`, `+`, `:`) — просто пропускается.
// Компоненты сравниваются поэлементно, недостающие — ноль.
//
// Отсюда (все факты сверены с живым `xbps-uhelper cmpver`, XBPS 0.59.1;
// всего 437 пар: официальная таблица xbps, края INT32 и 375 случайных —
// vercmp_test.go и проба сессии):
// «1.0» == «1.0.0», «1.0» == «1.0_0», «1.0~rc1» < «1.0» (rc = -1 < 0),
// «1.0pre1» == «1.0rc1» (pre и rc — один код), «1.0pl1» > «1.0»,
// «7.0.0_2» > «7.0.0_1», «1.2» < «1.10». У `~` ОТДЕЛЬНОЙ семантики нет —
// это пропускаемый байт, поэтому «1.0~1» > «1.0» (в pacman/rpm было бы
// наоборот): паритет с клиентом важнее «красоты».
//
// ПЕРЕПОЛНЕНИЕ — часть паритета: в dewey.c число копится в `int`
// (`n = n*10 + d`), то есть 32-битным, и прогон цифр больше 2^31 значение
// переполняет (в C это UB, на практике — модульная арифметика). Клиент
// сравнивает УЖЕ переполненные числа, причём и РАЗНОСТЬ компонентов тоже
// считается в `int` и переполняется: пару `xtools-2400127517_3` /
// `xtools-143b31` он считает как «2400127517 < 143» (отрицательное), а
// `foo-2147483648` рядом с `foo-1` — как большее (INT_MIN минус 1
// заворачивается в положительное). Повторяем int32-поведение осознанно:
// в индексе обязана остаться та версия, которую клиент считает новейшей, а
// «правильная» длинная арифметика дала бы ровно ту ошибку, ради которой
// дедуп и делается.

package xbps

import "strings"

// dewey-коды (dewey.c, «do not modify these values»).
const (
	deweyAlpha = -3
	deweyBeta  = -2
	deweyRC    = -1 // «pre» и «rc» — один код
	deweyDot   = 0  // «.» и «pl»
)

// deweyLetters — латинский алфавит в порядке dewey.c: индекс буквы + 1 —
// код компонента («a» → 1 … «z» → 26).
const deweyLetters = "abcdefghijklmnopqrstuvwxyz"

// CompareXbpsVer сравнивает два pkgver («имя-версия[_ревизия]») в порядке
// libxbps: <0 — a старше b, 0 — эквивалентны, >0 — a новее b.
//
// Имя сравнивается байтово, версии — алгоритмом dewey. Сам libxbps
// сравнивает строку pkgver целиком (док-комментарий xbps_cmpver: «no
// comparison of the basenames is done»), поэтому у РАЗНЫХ имён знак может
// расходиться с клиентским; для дедупа это неважно — там имена совпадают
// по построению (ключ — PkgName из props.plist).
//
// Мусорный вход компаратор не валидирует и не роняет: он сравнивает, а не
// проверяет формат — выбор записи при дедупе обязан быть детерминированным
// при любом входе (образец pacman.ComparePkgVer).
func CompareXbpsVer(a, b string) int {
	nameA, verA, errA := SplitPkgver(a)
	nameB, verB, errB := SplitPkgver(b)
	if errA == nil && errB == nil {
		if c := strings.Compare(nameA, nameB); c != 0 {
			return c
		}
		return parseDewey(verA).compare(parseDewey(verB))
	}
	// Неразобранный pkgver (мусор): сравнение тех же строк целиком — тот же
	// алгоритм, тот же детерминизм, без ошибок.
	return parseDewey(a).compare(parseDewey(b))
}

// deweyPart — компонент версии. В dewey.c это `int`, куда попадают и числа
// (n = n*10 + d), и коды модификаторов/букв (-3…26); храним то же самое —
// int32 с переполнением, как у клиента (см. шапку файла).
type deweyPart int32

// deweyVersion — разобранная версия: компоненты в порядке следования и
// ревизия `_N` (участвует в сравнении последней; отсутствие — ноль).
type deweyVersion struct {
	parts    []deweyPart
	revision deweyPart
}

// parseDewey разбирает строку версии на компоненты (dewey.c:mkversion).
func parseDewey(s string) deweyVersion {
	var v deweyVersion
	for i := 0; i < len(s); {
		i += v.component(s[i:])
	}
	return v
}

// component разбирает один компонент и возвращает число съеденных байт;
// нераспознанный байт съедается один и ни во что не вносится — так dewey
// (и клиент) обходится с `~`, `-`, `+`, `:`.
func (v *deweyVersion) component(num string) int {
	if isDigit(num[0]) {
		v.parts = append(v.parts, deweyNumber(num))
		return deweyDigits(num)
	}
	if code, size, ok := deweyModifier(num); ok {
		v.parts = append(v.parts, deweyPart(code))
		return size
	}
	if num[0] == '_' {
		v.revision = deweyNumber(num[1:])
		return 1 + deweyDigits(num[1:])
	}
	if isASCIIAlpha(num[0]) {
		// Буква — это ДВА компонента: ноль (Dot) и её номер в алфавите.
		v.parts = append(v.parts, deweyPart(deweyDot), deweyPart(deweyLetterIndex(num[0])))
		return 1
	}
	return 1
}

// deweyNumber — значение ведущего прогона цифр: n = n*10 + d в int32, как
// `int` в dewey.c (32 бита и на amd64-клиенте, и на 32-битных). Переполнение
// повторяем осознанно — см. шапку файла: клиент сравнивает именно такие
// значения, и «правильная» арифметика разошлась бы с ним на длинных прогонах.
func deweyNumber(s string) deweyPart {
	var n deweyPart
	for i := 0; i < len(s) && isDigit(s[i]); i++ {
		n = n*10 + deweyPart(s[i]-'0')
	}
	return n
}

// deweyDigits — длина ведущего прогона цифр (сколько байт съел deweyNumber).
func deweyDigits(s string) int {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return i
}

// deweyModifier — совпадение префикса num с таблицей модификаторов dewey
// (порядок таблицы: alpha, beta, pre, rc, pl, «.»; регистр не важен,
// strncasecmp не матчит префикс длиннее строки).
func deweyModifier(num string) (code, size int, ok bool) {
	switch lowerASCII(num[0]) {
	case 'a':
		if hasPrefixFold(num, "alpha") {
			return deweyAlpha, len("alpha"), true
		}
	case 'b':
		if hasPrefixFold(num, "beta") {
			return deweyBeta, len("beta"), true
		}
	case 'p':
		if hasPrefixFold(num, "pre") {
			return deweyRC, len("pre"), true
		}
		if hasPrefixFold(num, "pl") {
			return deweyDot, len("pl"), true
		}
	case 'r':
		if hasPrefixFold(num, "rc") {
			return deweyRC, len("rc"), true
		}
	case '.':
		return deweyDot, 1, true
	}
	return 0, 0, false
}

// compare сравнивает две разобранные версии: поэлементно (недостающий
// компонент — ноль, макрос DIGIT из dewey.c), затем ревизии.
func (v deweyVersion) compare(o deweyVersion) int {
	n := max(len(v.parts), len(o.parts))
	for i := range n {
		var a, b deweyPart // отсутствующий компонент — ноль
		if i < len(v.parts) {
			a = v.parts[i]
		}
		if i < len(o.parts) {
			b = o.parts[i]
		}
		if a != b {
			return signOfPart(a, b)
		}
	}
	return signOfPart(v.revision, o.revision)
}

// signOfPart — знак сравнения компонентов — у dewey.c это ВЫЧИТАНИЕ
// (`DIGIT(lhs) - DIGIT(rhs)` в `int`), и оно тоже переполняется: разность
// INT32_MIN - 1 заворачивается в положительное число. Знак берётся у
// переполненной разности — именно так клиент и решает (сверено:
// `foo-2147483648` против `foo-1` он считает БОЛЬШИМ, `foo-0` против
// `foo-2147483648` — меньшим). Поэтому вычитаем в int32, а не сравниваем:
// «правильное» сравнение разошлось бы с клиентом на этих краях.
func signOfPart(a, b deweyPart) int {
	switch d := a - b; {
	case d < 0:
		return -1
	case d > 0:
		return 1
	default:
		return 0
	}
}

// hasPrefixFold — префикс без учёта регистра (strncasecmp); префикс
// длиннее строки не совпадает (в C сравнение упирается в NUL).
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// lowerASCII — нижний регистр ASCII (вход dewey — байты версии, не руны).
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// isASCIIAlpha — латинская буква: dewey даёт код только буквам алфавита, а
// всё остальное (включая `~`, цифры других алфавитов, UTF-8) пропускает.
func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// deweyLetterIndex — номер буквы в алфавите (a → 1 … z → 26).
func deweyLetterIndex(b byte) int {
	return strings.IndexByte(deweyLetters, lowerASCII(b)) + 1
}
