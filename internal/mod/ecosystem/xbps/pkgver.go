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

// Разбор pkgver xbps: <pkgname>-<version>_<revision>. Имя пакета Void
// может содержать дефисы и цифры (`python3-pip`, `0ad`, `66-init`),
// поэтому наивное деление по первому/последнему дефису ломается.
// Граница имя/версия — последний дефис, за которым идёт цифра (libxbps,
// lib/pkgdb.c: pkg_name сканирует строку с конца). Версия и ревизия —
// только цифры в начале/ревизии соответственно.

package xbps

import (
	"strings"

	"khrazhevnik/internal/core/domain"
)

// SplitPkgver делит pkgver на имя пакета и версию. Имя может содержать
// дефисы и цифры, версия ОБЯЗАНА начинаться с цифры. Ревизия `_N` (N —
// цифры) необязательна, но `_`-суффикс с нецифровым (в т.ч. пустым)
// хвостом — ValidationError: ревизия — только цифры. Мусор (пусто, нет
// границы имя/версия, пустое имя) — ValidationError, не паника.
func SplitPkgver(pkgver string) (name, version string, err error) {
	if pkgver == "" {
		return "", "", pkgverError(pkgver, "пустая строка")
	}
	idx := splitIndex(pkgver)
	if idx < 0 {
		return "", "", pkgverError(pkgver, "нет дефиса, за которым версия начинается с цифры")
	}
	name, version = pkgver[:idx], pkgver[idx+1:]
	if name == "" {
		return "", "", pkgverError(pkgver, "пустое имя пакета")
	}
	if strings.IndexByte(version, '_') >= 0 {
		if _, _, ok := SplitRevision(version); !ok {
			return "", "", pkgverError(pkgver, "ревизия после «_» должна быть непустой последовательностью цифр")
		}
	}
	return name, version, nil
}

// SplitRevision делит version на upstream-часть и ревизию — последний
// `_`-суффикс из одних цифр. Если валидного хвоста нет, upstream — вся
// version, revision "", ok=false: у части пакетов ревизии нет, это не
// ошибка (`foo-1.0_` → ok=false, upstream «1.0_»).
func SplitRevision(version string) (upstream, revision string, ok bool) {
	idx := strings.LastIndexByte(version, '_')
	if idx < 0 || idx == len(version)-1 {
		return version, "", false
	}
	tail := version[idx+1:]
	for i := 0; i < len(tail); i++ {
		if !isDigit(tail[i]) {
			return version, "", false
		}
	}
	return version[:idx], tail, true
}

// Filename собирает имя файла пакета xbps: <pkgver>.<arch>.xbps. Поле
// filename в индексе отсутствует — клиент строит имя сам (libxbps,
// transaction_fetch.c), поэтому формула держится в одной точке для
// Enumerate (сессия 135) и генератора личных репо (сессия 141).
func Filename(pkgver, architecture string) string {
	return pkgver + "." + architecture + ".xbps"
}

// splitIndex возвращает индекс последнего дефиса, за которым идёт цифра
// (граница имя/версия libxbps), или -1.
func splitIndex(pkgver string) int {
	for i := len(pkgver) - 2; i >= 0; i-- {
		if pkgver[i] == '-' && isDigit(pkgver[i+1]) {
			return i
		}
	}
	return -1
}

// isDigit — ASCII-цифра. Намеренно сужено до 0-9: unicode-цифры в pkgver
// Void не встречаются, а SplitRevision должен считать ревизией только
// ASCII-последовательность.
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// pkgverError — типизированная ошибка разбора pkgver.
func pkgverError(value, reason string) error {
	return &domain.ValidationError{What: "pkgver", Value: value, Reason: reason}
}
