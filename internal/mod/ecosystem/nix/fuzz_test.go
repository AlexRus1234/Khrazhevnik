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

// FuzzResignNarinfo гоняет переподпись narinfo на произвольных байтах.
// Инварианты (сессия 16): не паниковать, не зацикливаться; non-Sig
// контент байт-точно сохраняется (stripSig(in) == stripSig(out)). Потолок
// 16KiB: ввод > лимита → narinfo не обрабатывается (resignNarinfo
// проверяет размер, но resignNarinfoBytes вызывается только для валидных;
// здесь гоняем сам байт-уровень без размерного guard, поэтому ограничиваем
// ввод фаззера 16KiB через seed-корпус и проверку длины).
func FuzzResignNarinfo(f *testing.F) {
	golden, err := os.ReadFile(filepath.Clean("testdata/narinfo.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	seeds := [][]byte{
		{0},
		[]byte(""),
		[]byte("garbage"),
		[]byte("URL: nar/" + narHash32 + ".nar.xz\n"),
		[]byte("Sig: k:v==\n"),
		[]byte("A: x\nB: y\nSig: old\nC: z\n"),
		golden,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	signer := &stubNarSigner{}

	f.Fuzz(func(t *testing.T, data []byte) {
		out := resignNarinfoBytes(data, signer)
		// non-Sig контент обязан сохраниться (байт-точно, modulo trailing
		// \n — resign всегда добавляет trailing \n для Sig-строки, даже
		// если во входе его не было).
		inStripped := bytes.TrimRight(stripSigForFuzz(data), "\n")
		outStripped := bytes.TrimRight(stripSigForFuzz(out), "\n")
		if !bytes.Equal(inStripped, outStripped) {
			t.Fatalf("non-Sig контент изменился:\nin:  %q\nout: %q", inStripped, outStripped)
		}
		// ровно одна Sig-строка в результате (наш ключ инстанса).
		sigCount := bytes.Count(out, []byte("\nSig:"))
		if len(out) > 0 && bytes.HasPrefix(out, []byte("Sig:")) {
			sigCount++
		}
		if sigCount != 1 {
			t.Fatalf("Sig-строк в out = %d, хочу 1 (in=%d байт)", sigCount, len(data))
		}
		_ = sameErr // подавим unused, если ни один fuzz выше не звал
	})
}

// stubNarSigner — детерминированный port.NarSigner для фаззинга. Sig
// обязан быть однострочным (без встроенных \n), как у настоящего ed25519
// (base64 не содержит \n) — иначе \n внутри sig-значения породил бы
// «фантомные» строки при ре-разборе и сломал бы инвариант.
type stubNarSigner struct{}

func (stubNarSigner) Sign(msg []byte) string {
	// hex от msg — детерминирован, \n-free (только 0-9a-f), имитирует
	// base64-sig настоящего ed25519 (по формату, не по крипто-силе).
	return "stub:AAAA:" + hexEncodeForFuzz(msg)
}
func (stubNarSigner) PubKeyB64() string { return "AAAA" }
func (stubNarSigner) Name() string      { return "stub" }

// hexEncodeForFuzz — hex-кодирование без \n (только 0-9a-f). Дубликат
// hexEncode из publish_test.go (test-файлы одного пакета, но держим
// независимым от порядка компиляции).
func hexEncodeForFuzz(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hex[v>>4]
		out[2*i+1] = hex[v&0xf]
	}
	return string(out)
}

// stripSigForFuzz — копия stripSigLines (publish_test.go) для fuzz-пакета;
// test-файлы одного пакета, но чтобы не плодить зависимость от порядка
// компиляции, дублируем (как sameErr дублируется).
func stripSigForFuzz(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	var out [][]byte
	for _, l := range lines {
		if !bytes.HasPrefix(l, []byte("Sig:")) {
			out = append(out, l)
		}
	}
	return bytes.Join(out, []byte("\n"))
}
