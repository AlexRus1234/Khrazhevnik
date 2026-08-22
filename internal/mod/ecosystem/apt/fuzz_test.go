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

package apt

import (
	"bytes"
	"errors"
	"iter"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseStanzas гоняет парсер на произвольных байтах: инварианты —
// не паниковать, не зацикливаться (таймаут теста ловит), и повторный
// разбор тех же байт даёт тот же набор записей. Потолки стянуты до
// маленьких значений, чтобы фаззер не падал на собственном лимите
// памяти, успевая за 20с исследовать много разных форм.
func FuzzParseStanzas(f *testing.F) {
	// Посев-корпус: золотые фикстуры + несколько синтетических форм
	// (пустой, CRLF, только-поля, вложенные продолжения, битый UTF-8).
	seeds := []string{
		"",
		"Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n\n",
		"Package: crlf\r\nVersion: 1\r\nDescription: s\r\n long\r\n\r\n",
		"Field: value\n no colon line should not crash but error\n",
		"Description: short\n line1\n  line2 indented\n .\n blank line\n",
		"X: \xff\xfe\nY: ok\n\n",
		"\n\n\n",
		": nospace\nNext: ok\n",
	}
	for _, p := range []string{
		"testdata/Packages.golden",
		"testdata/Release.golden",
		"testdata/empty.golden",
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

	// fuzzLimits — стянутые потолки: маленький лимит записей и полей,
	// чтобы за отведённое время покрыть больше входов, а не вязнуть в
	// одном гигантском массиве. Локальная переменная, а не package var:
	// фазз-инвариант к размеру, а производство гоняет Stanzas (дефолт).
	lim := limits{stanzas: 1024, field: 1 << 14, name: 256}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := collect(stanzas(bytes.NewReader(data), lim))
		// Повторный разбор тех же байт обязан дать идентичный результат —
		// детерминизм парсера. Разница означает скрытое состояние (нельзя).
		second, secondErr := collect(stanzas(bytes.NewReader(data), lim))
		if !sameErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
		}
		for i := range first {
			if !first[i].Equal(second[i]) {
				t.Fatalf("запись %d differs между прогонами:\n %+v\n vs\n %+v", i, first[i], second[i])
			}
		}
	})
}

// collect вытягивает итератор в срез; кладёт свежий reader на каждый
// прогон (иначе первый забрал бы данные, а второй видел бы пустоту).
func collect(it iter.Seq2[*Stanza, error]) ([]*Stanza, error) {
	var out []*Stanza
	var lastErr error
	for s, err := range it {
		if err != nil {
			lastErr = err
			break
		}
		out = append(out, s)
	}
	return out, lastErr
}

// sameErr сравнивает ошибки через errors.Is обе стороны: nil-nil,
// одинаковый sentinel, либо обе не-nil и равны.
func sameErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return errors.Is(a, b) || errors.Is(b, a)
}
