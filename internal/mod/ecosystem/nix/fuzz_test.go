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

package nix

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseNarinfo гоняет парсер narinfo на произвольных байтах.
// Инварианты (сессия 13):
//   - без паники на любом вводе;
//   - размер записи < 16KiB: ввод > лимита → ErrNarinfoTooLarge;
//   - все пути в URL:-поле валидны относительно /nar/ или запись
//     отброшена: WantNar либо пусто, либо /nar/<32hex>.nar[.xz];
//   - детерминизм: повторный разбор тех же байт даёт тот же результат.
func FuzzParseNarinfo(f *testing.F) {
	// Посев-корпус: золотой narinfo + синтетика + битые варианты.
	golden, err := os.ReadFile(filepath.Clean("testdata/narinfo.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	seeds := [][]byte{
		{0},
		[]byte(""),
		[]byte("garbage not a narinfo"),
		[]byte("URL: nar/" + narHash32 + ".nar.xz\n"),
		[]byte("URL: nar/ffffffffffffffffffffffffffffffff.nar\nSig: k:v==\n"),
		[]byte("URL: pool/" + narHash32 + ".nar.xz\n"),  // чужой префикс
		[]byte("URL: nar/foo.nar.xz\n"),                 // невалидный хеш
		[]byte("FileSize: not-a-number\nNarSize: 5\n"),  // битое число
		[]byte("no colons here at all\njust text"),      // без «:»
		[]byte("Sig: cache.example.org-1:abcdef==\n"),   // вторая «:»
		[]byte("URL: nar/" + narHash32 + ".nar.xz\r\n"), // CRLF
		golden,
	}
	// граничный корпус: ровно лимит и лимит+1.
	seeds = append(seeds, bytes.Repeat([]byte("a"), maxNarinfoSize))
	seeds = append(seeds, bytes.Repeat([]byte("a"), maxNarinfoSize+1))
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, ferr := ParseNarinfo(bytes.NewReader(data))
		second, serr := ParseNarinfo(bytes.NewReader(data))
		if !sameErr(ferr, serr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", ferr, serr)
		}
		if !narinfoEqual(first, second) {
			t.Fatalf("недетерминированный разбор: %+v vs %+v", first, second)
		}
		// размер записи < 16KiB: ввод > лимита → ErrNarinfoTooLarge.
		if len(data) > maxNarinfoSize {
			if !sameErr(ferr, ErrNarinfoTooLarge) {
				t.Fatalf("ввод %d байт (> %d): ждал ErrNarinfoTooLarge, got %v", len(data), maxNarinfoSize, ferr)
			}
			return
		}
		if ferr != nil {
			// Прочие ошибки (только ErrBadNarinfo от ридера) — штатны.
			return
		}
		// Инвариант путей: WantNar либо пусто (запись отброшена), либо
		// валидный /nar/<32hex>.nar[.xz] — никаких мусорных путей наружу.
		nar := WantNar(first)
		if nar == "" {
			return
		}
		rest, ok := strings.CutPrefix(nar, "/nar/")
		if !ok {
			t.Fatalf("WantNar = %q: нет префикса /nar/", nar)
		}
		if !validNarName(rest) {
			t.Fatalf("WantNar = %q: не валидный nar-путь (хеш/суффикс)", nar)
		}
	})
}
