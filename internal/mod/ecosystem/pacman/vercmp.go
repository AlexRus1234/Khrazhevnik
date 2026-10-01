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

// Сравнение версий pacman-пакетов по семантике libalpm
// (alpm_pkg_vercmp). Нужно генератору личного репо: .db обязан держать
// не более одной записи на %NAME%, и версию выбирает ГЕНЕРАТОР, а
// клиент потом сверяет имя каталога/файл с %NAME%/%VERSION% — порядок
// обязан совпадать с клиентским, иначе pacman видит не ту версию или
// падает на «version mismatch» (дефект волны 1.3.2: две версии одного
// пакета в storage ломали `pacman -S` для всех клиентов).
//
// Алгоритм — порт libalpm/lib/libalpm/version.c (parseEVR +
// rpmvercmp пакета pacman, он же «adopted from rpm 4.8.1»). Это НЕ
// RPM-алгоритм: ни tilde («~»), ни caret («^»), ни таблицы
// pre/post-release здесь нет — версии делятся на alnum-сегменты, а
// нецифровой хвост сравнивается побайтово, поэтому «1.0alpha1» и
// «1.0rc1» старше «1.0» (остаток алфавитного хвоста против пустого),
// а «1.0post1» — тоже старше. Паритет с клиентом важнее «красоты»
// таблицы: любое расхождение = не та версия в индексе.
package pacman

import "strings"

// ComparePkgVer сравнивает две спецификации версии
// («[epoch:]version[-release]») в порядке libalpm: <0 — a старше b,
// 0 — эквивалентны, >0 — a новее b.
//
// Пустая или некорректная версия не паникует и не даёт ошибку:
// компаратор сравнивает строки, а не валидирует их — выбор записи при
// дедупе обязан быть детерминированным при любом входе.
func ComparePkgVer(a, b string) int {
	if a == b {
		return 0
	}
	e1, v1, r1, hasRel1 := parseEVR(a)
	e2, v2, r2, hasRel2 := parseEVR(b)
	if c := rpmVerCmp(e1, e2); c != 0 {
		return c
	}
	if c := rpmVerCmp(v1, v2); c != 0 {
		return c
	}
	// Release участвует, только если он есть у обоих (в libalpm —
	// ненулевой указатель): «1.0» и «1.0-1» для alpm эквивалентны.
	if !hasRel1 || !hasRel2 {
		return 0
	}
	return rpmVerCmp(r1, r2)
}

// parseEVR разбирает «[epoch:]version[-release]» как libalpm
// (version.c:parseEVR): epoch — ведущие цифры перед «:» (нет «:» → 0),
// release — хвост после ПОСЛЕДНЕГО «-» начиная с конца цифровой
// последовательности (strrchr в libalpm; нет «-» → release отсутствует).
func parseEVR(evr string) (epoch, version, release string, hasRel bool) {
	i := 0
	for i < len(evr) && isASCIIDigit(evr[i]) {
		i++
	}
	lastDash := -1
	for j := i; j < len(evr); j++ {
		if evr[j] == '-' {
			lastDash = j
		}
	}
	epoch, start := "0", 0
	if i < len(evr) && evr[i] == ':' {
		if e := evr[:i]; e != "" {
			epoch = e
		}
		start = i + 1
	}
	end := len(evr)
	if lastDash >= 0 {
		release, hasRel = evr[lastDash+1:], true
		end = lastDash
	}
	if end < start {
		end = start
	}
	return epoch, evr[start:end], release, hasRel
}

// rpmVerCmp — сравнение двух версий по алгоритму libalpm (version.c:
// rpmvercmp): строки делятся не-alnum символами на alnum-сегменты;
// цифровой сегмент новее алфавитного; цифровые сравниваются по длине
// (после отбрасывания ведущих нулей), затем побайтово; алфавитные —
// побайтово (ASCII); длина разделителей решает исход до сравнения
// сегментов.
//
//nolint:gocyclo // порт libalpm: паритет по веткам важнее метрики
func rpmVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0   // начало текущих сегментов
	ptr1, ptr2 := 0, 0 // концы предыдущих сегментов (границы разделителей)
	for one < len(a) && two < len(b) {
		ptr1, ptr2 = one, two
		for one < len(a) && !isASCIIAlnum(a[one]) {
			one++
		}
		for two < len(b) && !isASCIIAlnum(b[two]) {
			two++
		}
		if one >= len(a) || two >= len(b) {
			break
		}
		// Разная длина разделителей — тоже различие версий.
		if d1, d2 := one-ptr1, two-ptr2; d1 != d2 {
			if d1 < d2 {
				return -1
			}
			return 1
		}
		start1, start2 := one, two
		isnum := isASCIIDigit(a[start1])
		end1, end2 := start1, start2
		if isnum {
			for end1 < len(a) && isASCIIDigit(a[end1]) {
				end1++
			}
			for end2 < len(b) && isASCIIDigit(b[end2]) {
				end2++
			}
		} else {
			for end1 < len(a) && isASCIIAlpha(a[end1]) {
				end1++
			}
			for end2 < len(b) && isASCIIAlpha(b[end2]) {
				end2++
			}
		}
		// У b сегмент другого типа: цифровой всегда новее алфавитного.
		if end2 == start2 {
			if isnum {
				return 1
			}
			return -1
		}
		if isnum {
			// Длиннее после отбрасывания ведущих нулей — больше.
			s1 := strings.TrimLeft(a[start1:end1], "0")
			s2 := strings.TrimLeft(b[start2:end2], "0")
			if len(s1) != len(s2) {
				if len(s1) < len(s2) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(s1, s2); c != 0 {
				return c
			}
		} else if c := strings.Compare(a[start1:end1], b[start2:end2]); c != 0 {
			return c
		}
		one, two = end1, end2
	}
	// Финальная развязка libalpm: остаток алфавитного хвоста младше
	// пустоты («1.0alpha1» < «1.0»), а остаток цифрового хвоста — старше.
	leftEnd, rightEnd := one >= len(a), two >= len(b)
	switch {
	case leftEnd && rightEnd:
		return 0
	case leftEnd && !(two < len(b) && isASCIIAlpha(b[two])):
		return -1
	case !leftEnd && isASCIIAlpha(a[one]):
		return -1
	default:
		return 1
	}
}

// isASCIIAlpha — [A-Za-z] (класс isalpha C-локали).
func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isASCIIAlnum — alnum-класс C-локали: [0-9A-Za-z]. Именно так libalpm
// делит версии на сегменты; байты >127 в UTF-8-локали не alnum.
func isASCIIAlnum(b byte) bool {
	return isASCIIDigit(b) || isASCIIAlpha(b)
}
