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

package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration — time.Duration в TOML/env-строках вида "5m", "8h".
// Обёртка-структура ради UnmarshalText (go-toml применяет его к
// строковым значениям), поле Duration читается напрямую.
type Duration struct {
	time.Duration
}

// UnmarshalText парсит TOML-строку time.ParseDuration'ом.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("конфигурация: некорректный duration %q: %w", string(b), err)
	}
	d.Duration = v
	return nil
}

// ByteSize — размер в байтах; TOML/env-строки вида "20GiB", "512MiB",
// "1024" (голое число — байты).
type ByteSize struct {
	Bytes int64
}

// UnmarshalText парсит TOML-строку размера.
func (b *ByteSize) UnmarshalText(p []byte) error {
	n, err := parseByteSize(string(p))
	if err != nil {
		return fmt.Errorf("конфигурация: некорректный размер %q: %w", string(p), err)
	}
	b.Bytes = n
	return nil
}

// parseByteSize понимает двоичные (KiB..PiB) и десятичные (kB..TB)
// суффиксы, регистр не важен; без суффикса — байты.
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("пустое значение размера")
	}
	num, unit := splitAtFirstLetter(s)
	if unit == "" {
		n, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("ожидается число или число с суффиксом: %w", err)
		}
		return n, nil
	}
	mult, ok := byteUnitMult(unit)
	if !ok {
		return 0, fmt.Errorf("неизвестный суффикс %q (доступны B, KiB..PiB, kB..TB)", unit)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("некорректное число %q: %w", num, err)
	}
	return int64(f * float64(mult)), nil
}

// byteUnitMult — множитель суффикса размера.
func byteUnitMult(unit string) (int64, bool) {
	switch strings.ToLower(unit) {
	case "b":
		return 1, true
	case "kib":
		return 1 << 10, true
	case "mib":
		return 1 << 20, true
	case "gib":
		return 1 << 30, true
	case "tib":
		return 1 << 40, true
	case "pib":
		return 1 << 50, true
	case "kb":
		return 1000, true
	case "mb":
		return 1000 * 1000, true
	case "gb":
		return 1000 * 1000 * 1000, true
	case "tb":
		return 1000 * 1000 * 1000 * 1000, true
	}
	return 0, false
}

// splitAtFirstLetter делит строку на числовую часть и суффикс.
func splitAtFirstLetter(s string) (num, unit string) {
	i := 0
	for i < len(s) {
		c := s[i]
		isLetter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if isLetter {
			break
		}
		i++
	}
	return s[:i], s[i:]
}
