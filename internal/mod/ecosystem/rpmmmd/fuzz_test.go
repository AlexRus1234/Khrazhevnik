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

package rpmmmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseRepomd гоняет парсер на произвольных байтах: инварианты —
// не паниковать, не зацикливаться (таймаут теста ловит), и повторный
// разбор тех же байт даёт тот же набор записей. Потолки стянуты до
// маленьких значений, чтобы фаззер не вяз в одном гигантском вводе,
// успевая за 20с исследовать много разных форм (правило сессии 08).
func FuzzParseRepomd(f *testing.F) {
	// Посев-корпус: золотые фикстуры + синтетические формы (пустой,
	// битый, незакрытые теги, XXE-попытка, вложенные теги,attr-only).
	seeds := []string{
		"",
		"<repomd></repomd>",
		"<repomd><data type=\"primary\"><location href=\"r/x.xml.gz\"/></data></repomd>",
		"<repomd><data type=\"primary\"><checksum>abc</checksum>",
		"<repomd><data><x><y><z></z></y></x></data></repomd>",
		"<?xml version=\"1.0\"?><repomd><revision>r</revision><data type=\"t\"/></repomd>",
		"<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><repomd><data><c>&x;</c></data></repomd>",
		"<repomd><data type=\"a\"><location href=\"/abs/path\"/></data></repomd>",
		"<repomd><data type=\"a\"><location href=\"https://x/y\"/></data></repomd>",
		"\xff\xfe<repomd/>", // битый UTF-8 в прологе
		"<repomd><data type=\"" + string(bytes.Repeat([]byte("x"), 256)) + "\"/></repomd>",
	}
	for _, p := range []string{
		"testdata/repomd.golden",
		"testdata/repomd-empty.golden",
	} {
		b, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			f.Fatalf("чтение посева %s: %v", p, err)
		}
		seeds = append(seeds, string(b))
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	// fuzzLimits — стянутые потолки: маленький лимит data-элементов и
	// текста, чтобы за отведённое время покрыть больше входов, а не
	// вязнуть в одном массиве.
	lim := parseLimits{data: 256, text: 1 << 14}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := collectRepomd(parseRepomd(bytes.NewReader(data), lim))
		// Повторный разбор тех же байт обязан дать идентичный результат —
		// детерминизм парсера. Разница означает скрытое состояние (нельзя).
		second, secondErr := collectRepomd(parseRepomd(bytes.NewReader(data), lim))
		if !sameErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("число data-элементов скачет: %d vs %d", len(first), len(second))
		}
		for i := range first {
			if !dataElementsEqual(first[i], second[i]) {
				t.Fatalf("элемент %d differs между прогонами:\n %+v\n vs\n %+v", i, first[i], second[i])
			}
		}
	})
}

// dataElementsEqual — структурное сравнение (DataElement без плавающих
// полей: все поля детерминированы парсером).
func dataElementsEqual(a, b DataElement) bool {
	return a == b
}

// sameErr сравнивает ошибки: nil-nil, совпадение sentinel'а через
// errors.Is (для ErrUnexpectedEOF/ErrTooManyData/…), либо — для
// обёрнутых (ErrBadLocation с href) и сырых xml.SyntaxError, где каждый
// прогон создаёт новый экземпляр — равенство текста Error(). Текст
// детерминирован, если парсер не имеет скрытого состояния.
func sameErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if errors.Is(a, b) || errors.Is(b, a) {
		return true
	}
	return a.Error() == b.Error()
}

// FuzzParseRPMHeader гоняет мини-парсер RPM-заголовков на произвольных
// байтах (байтовый формат — фаззинг обязателен, см. сессию 16).
// Инварианты: не паниковать, не зацикливаться (таймаут ловит), повторный
// разбор тех же байт даёт тот же результат (детерминизм). Потолки
// nindex/dataLen уже в парсере — фаззер не передаёт лимиты.
func FuzzParseRPMHeader(f *testing.F) {
	// Посев-корпус: валидный .rpm (buildRPM) + битые варианты.
	seeds := [][]byte{
		{0},
		[]byte(""),
		[]byte("not an rpm"),
		// lead magic без продолжения.
		{0xed, 0xab, 0xee, 0xdb},
	}
	// lead (magic + нули до 96 байт) без sig/main header — обрезка.
	leadOnly := make([]byte, leadSize)
	leadOnly[0], leadOnly[1], leadOnly[2], leadOnly[3] = 0xed, 0xab, 0xee, 0xdb
	leadOnly[4] = 3
	seeds = append(seeds, leadOnly)
	// Валидный .rpm через buildRPM (тестовый helper gen_test.go).
	seeds = append(seeds, buildRPM("foo", "1.0", "1", "x86_64", "test", 4096, 1724323200))
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, ferr := ParseRPMHeader(bytes.NewReader(data))
		second, serr := ParseRPMHeader(bytes.NewReader(data))
		if !sameErr(ferr, serr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", ferr, serr)
		}
		if (first == nil) != (second == nil) {
			t.Fatalf("недетерминированный nil: %v vs %v", first, second)
		}
		if first == nil {
			return
		}
		if first.Name != second.Name || first.Version != second.Version ||
			first.Release != second.Release || first.Arch != second.Arch ||
			first.Summary != second.Summary || first.Size != second.Size ||
			first.BuildTime != second.BuildTime || first.Epoch != second.Epoch {
			t.Fatalf("недетерминированный разбор: %+v vs %+v", first, second)
		}
	})
}
