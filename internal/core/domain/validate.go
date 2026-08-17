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

// Валидаторы значений из внешнего мира. ValidateKey — единая точка
// path-traversal: все ключи хранения, пришедшие из запросов, обязаны
// пройти её до попадания в Storage.

package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Ограничения длин: защищают fs-хранилище от безумных путей и БД —
// от мусора.
const (
	maxKeyLen      = 1024
	maxUsernameLen = 32
	maxRepoNameLen = 64
)

// ValidateKey проверяет ключ единого namespace хранения: только
// [a-z0-9/._-], без «..», без ведущего/хвостового «/», без пустых
// сегментов, длиной до maxKeyLen. Возвращает *InvalidKeyError со всеми
// нарушениями сразу (errors.Join причин).
func ValidateKey(key string) error {
	var reasons []error
	if key == "" {
		reasons = append(reasons, errors.New("пустой ключ"))
	}
	if len(key) > maxKeyLen {
		reasons = append(reasons, fmt.Errorf("длиннее %d байт", maxKeyLen))
	}
	if strings.HasPrefix(key, "/") {
		reasons = append(reasons, errors.New("ведущий «/»"))
	}
	if strings.HasSuffix(key, "/") {
		reasons = append(reasons, errors.New("хвостовой «/»"))
	}
	if strings.Contains(key, "..") {
		reasons = append(reasons, errors.New("сегмент «..»"))
	}
	for i := 0; i < len(key); i++ {
		if !allowedKeyByte(key[i]) {
			reasons = append(reasons, fmt.Errorf("символ %q на позиции %d", key[i], i))
			break // по одному «плохому символу» достаточно для диагноза
		}
	}
	// Пустые сегменты («//») и «.» — отдельные нарушения: «//»
	// выродилось бы в пустой элемент пути, а «.» даёт алиасинг
	// ключей в fs-хранилище (a/./b == a/b).
	for _, seg := range strings.Split(key, "/") {
		if seg == "" && key != "" {
			reasons = append(reasons, errors.New("пустой сегмент"))
			break
		}
		if seg == "." {
			reasons = append(reasons, errors.New("сегмент «.»"))
			break
		}
	}
	if len(reasons) > 0 {
		return &InvalidKeyError{Key: key, Reasons: reasons}
	}
	return nil
}

// allowedKeyByte — whitelist байтов ключа; %, верхний регистр, «\»,
// нулевые байты и прочее отсекаются здесь.
func allowedKeyByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '/' || b == '.' || b == '_' || b == '-':
		return true
	}
	return false
}

// ValidateUsername проверяет имя пользователя: [a-z0-9._-], начинается
// и кончается буквоцифрой, без «..», 1..32 байт.
func ValidateUsername(name string) error {
	return validateSlug("имя пользователя", name, maxUsernameLen)
}

// ValidateRepoName проверяет имя личного репозитория: те же правила,
// что у username, но до 64 байт.
func ValidateRepoName(name string) error {
	return validateSlug("имя репозитория", name, maxRepoNameLen)
}

// validateSlug — общая проверка slug-оподобных имён.
func validateSlug(what, name string, maxLen int) error {
	if name == "" {
		return &ValidationError{What: what, Value: name, Reason: "пустое"}
	}
	if len(name) > maxLen {
		return &ValidationError{What: what, Value: name, Reason: fmt.Sprintf("длиннее %d байт", maxLen)}
	}
	if strings.Contains(name, "..") {
		return &ValidationError{What: what, Value: name, Reason: "содержит «..»"}
	}
	if !isSlugByte(name[0]) {
		return &ValidationError{What: what, Value: name, Reason: "начинается не с буквоцифры"}
	}
	if !isSlugByte(name[len(name)-1]) {
		return &ValidationError{What: what, Value: name, Reason: "заканчивается не буквоцифрой"}
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if !isSlugByte(b) && b != '.' && b != '_' && b != '-' {
			return &ValidationError{What: what, Value: name, Reason: fmt.Sprintf("символ %q на позиции %d", b, i)}
		}
	}
	return nil
}

// isSlugByte — буква или цифра (края slug-а).
func isSlugByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// NormalizeScope разбирает scope API-токена и возвращает каноническую
// форму: «admin» либо «repo:<uint>:write» (ведущие нули срезаются:
// «repo:007:write» → «repo:7:write»). Всё прочее — ошибка.
func NormalizeScope(s string) (Scope, error) {
	if s == string(ScopeAdmin) {
		return ScopeAdmin, nil
	}
	const (
		kindRepo = "repo:"
		sufWrite = ":write"
	)
	if len(s) > len(kindRepo)+len(sufWrite) &&
		strings.HasPrefix(s, kindRepo) && strings.HasSuffix(s, sufWrite) {
		num := s[len(kindRepo) : len(s)-len(sufWrite)]
		if id, err := strconv.ParseUint(num, 10, 63); err == nil {
			return Scope(fmt.Sprintf("repo:%d:write", id)), nil
		}
	}
	return "", &ValidationError{What: "scope", Value: s, Reason: "ожидается «admin» или «repo:<id>:write»"}
}
