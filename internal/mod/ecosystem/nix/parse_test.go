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
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// narHash32 — валидный 32-символьный nix-base32 хеш store path для
// тестов (алфавит nix без e/o/t/u — как у реального nix). Hex-хеши
// ('e' внутри) валидными nix-хешами не являются.
const narHash32 = "x0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y"

// narFileHash52 — валидный 52-символьный nix-base32 fileHash nar-архива
// (sha256 сжатого файла, (256−1)/5+1 = 52 символа — как у реального nix).
const narFileHash52 = "x0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9yx0vm1mkfnqrq3hxjcp2w"

// mustReadTestdata читает файл из testdata/.
func mustReadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("чтение testdata/%s: %v", name, err)
	}
	return b
}

func TestParseNarinfoGolden(t *testing.T) {
	data := mustReadTestdata(t, "narinfo.golden")
	n, err := ParseNarinfo(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	want := &Narinfo{
		StorePath:   "/nix/store/" + narHash32 + "-hello-2.12.1",
		URL:         "nar/" + narFileHash52 + ".nar.xz",
		Compression: "xz",
		FileHash:    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		FileSize:    1024,
		NarHash:     "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		NarSize:     2048,
		References:  []string{"f0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-glibc-2.39"},
		Deriver:     narHash32 + "-hello-2.12.1.drv",
		Sig:         "cache.example.org-1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef==",
	}
	if !narinfoEqual(n, want) {
		t.Fatalf("ParseNarinfo = %+v, хочу %+v", n, want)
	}
}

func TestParseNarinfoSigKeepsSecondColon(t *testing.T) {
	// Sig: <key>:<base64> — значение содержит вторую «:»; парсер должен
	// сохранить её целиком (Cut по первой «:»).
	n, err := ParseNarinfo(bytes.NewReader([]byte(
		"Sig: cache.nixos.org-1:abcdef==\n")))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	if n.Sig != "cache.nixos.org-1:abcdef==" {
		t.Errorf("Sig = %q, хочу с сохранённой второй «:»", n.Sig)
	}
}

func TestParseNarinfoFirstFieldWins(t *testing.T) {
	// дубль поля — первое значение выигрывает (дубли игнорируются).
	n, err := ParseNarinfo(bytes.NewReader([]byte(
		"URL: nar/" + narFileHash52 + ".nar.xz\n" +
			"URL: nar/" + narFileHash52[:51] + "y.nar.xz\n")))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	if n.URL != "nar/"+narFileHash52+".nar.xz" {
		t.Errorf("URL = %q (первое должно выиграть)", n.URL)
	}
}

func TestParseNarinfoUnknownKeyIgnored(t *testing.T) {
	// неизвестный ключ — forward-compat: игнорируется, парсер не падает.
	n, err := ParseNarinfo(bytes.NewReader([]byte(
		"FutureField: something\nURL: nar/" + narFileHash52 + ".nar.xz\n")))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	if n.URL != "nar/"+narFileHash52+".nar.xz" {
		t.Errorf("URL = %q (неизвестный ключ не должен ломать)", n.URL)
	}
}

func TestParseNarinfoLineWithoutColon(t *testing.T) {
	// строка без «:» — tolerant: игнорируется, парсер не падает.
	n, err := ParseNarinfo(bytes.NewReader([]byte(
		"this line has no colon\nURL: nar/" + narFileHash52 + ".nar.xz\n")))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	if n.URL != "nar/"+narFileHash52+".nar.xz" {
		t.Errorf("URL = %q", n.URL)
	}
}

func TestParseNarinfoCRLF(t *testing.T) {
	// CRLF-окончания — \r срезается, парсер не ломается.
	data := []byte("URL: nar/" + narFileHash52 + ".nar.xz\r\nCompression: xz\r\n")
	n, err := ParseNarinfo(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseNarinfo CRLF: %v", err)
	}
	if n.URL != "nar/"+narFileHash52+".nar.xz" {
		t.Errorf("URL = %q (\\r не срезан?)", n.URL)
	}
	if n.Compression != "xz" {
		t.Errorf("Compression = %q", n.Compression)
	}
}

func TestParseNarinfoLastLineNoNewline(t *testing.T) {
	// последняя строка без \n — всё равно разбирается (tolerant).
	n, err := ParseNarinfo(bytes.NewReader([]byte("URL: nar/" + narFileHash52 + ".nar.xz")))
	if err != nil {
		t.Fatalf("ParseNarinfo без \\n: %v", err)
	}
	if n.URL != "nar/"+narFileHash52+".nar.xz" {
		t.Errorf("URL = %q", n.URL)
	}
}

func TestParseNarinfoEmpty(t *testing.T) {
	// пустой ввод — пустой Narinfo, не ошибка.
	n, err := ParseNarinfo(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("ParseNarinfo пустой: %v", err)
	}
	if n == nil || n.URL != "" {
		t.Errorf("пустой narinfo дал %+v, хочу пустой", n)
	}
}

func TestParseNarinfoGarbageNoPanic(t *testing.T) {
	// произвольный мусор — без паники, ошибка или пустой результат.
	_, _ = ParseNarinfo(bytes.NewReader([]byte("garbage not a narinfo at all")))
	// повторный разбор тех же байт — детерминизм.
	first, ferr := ParseNarinfo(bytes.NewReader([]byte("garbage")))
	second, serr := ParseNarinfo(bytes.NewReader([]byte("garbage")))
	if !sameErr(ferr, serr) {
		t.Fatalf("недетерминированная ошибка: %v vs %v", ferr, serr)
	}
	if !narinfoEqual(first, second) {
		t.Fatalf("недетерминированный разбор мусора")
	}
}

func TestParseNarinfoBadFileSizeIgnored(t *testing.T) {
	// битое числовое поле — tolerant: 0, не ошибка.
	n, err := ParseNarinfo(bytes.NewReader([]byte(
		"FileSize: not-a-number\nNarSize: 2048\n")))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	if n.FileSize != 0 {
		t.Errorf("FileSize = %d, хочу 0 (битое значение)", n.FileSize)
	}
	if n.NarSize != 2048 {
		t.Errorf("NarSize = %d, хочу 2048", n.NarSize)
	}
}

func TestParseNarinfoMultipleReferences(t *testing.T) {
	n, err := ParseNarinfo(bytes.NewReader([]byte(
		"References: aaa-foo bbb-bar ccc-baz\n")))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	want := []string{"aaa-foo", "bbb-bar", "ccc-baz"}
	if len(n.References) != len(want) {
		t.Fatalf("References = %+v, хочу %d", n.References, len(want))
	}
	for i, w := range want {
		if n.References[i] != w {
			t.Errorf("References[%d] = %q, хочу %q", i, n.References[i], w)
		}
	}
}

func TestParseNarinfoTooLarge(t *testing.T) {
	// narinfo длиннее 16KiB — ErrNarinfoTooLarge.
	big := bytes.Repeat([]byte("X: y\n"), (maxNarinfoSize/4)+100)
	_, err := ParseNarinfo(bytes.NewReader(big))
	if !errors.Is(err, ErrNarinfoTooLarge) {
		t.Fatalf("ожидалась ErrNarinfoTooLarge, получено %v", err)
	}
}

func TestParseNarinfoExactlyAtLimit(t *testing.T) {
	// narinfo ровно 16KiB — валиден (не превышает), не ошибка размера.
	data := bytes.Repeat([]byte("a"), maxNarinfoSize)
	_, err := ParseNarinfo(bytes.NewReader(data))
	if err != nil {
		t.Errorf("narinfo ровно 16KiB не должен ошибаться, got %v", err)
	}
}

func TestParseNarinfoReaderError(t *testing.T) {
	// ридер, падающий посреди — ErrBadNarinfo-обёртка.
	r := &errReader{data: []byte("URL: nar/" + narHash32 + ".nar.xz\n"), err: io.ErrUnexpectedEOF}
	_, err := ParseNarinfo(r)
	if err == nil {
		t.Fatal("ожидалась прокиданная ошибка ридера, получено nil")
	}
	if !errors.Is(err, ErrBadNarinfo) {
		t.Fatalf("ошибка = %v, хочу ErrBadNarinfo-обёртку", err)
	}
}

func TestParseNarinfoDeterminism(t *testing.T) {
	// повторный разбор того же потока обязан дать идентичный результат.
	data := mustReadTestdata(t, "narinfo.golden")
	first, ferr := ParseNarinfo(bytes.NewReader(data))
	second, serr := ParseNarinfo(bytes.NewReader(data))
	if !sameErr(ferr, serr) {
		t.Fatalf("недетерминированная ошибка: %v vs %v", ferr, serr)
	}
	if !narinfoEqual(first, second) {
		t.Fatalf("повторный разбор дал разные результаты")
	}
}

func TestIsNixBase32(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{narHash32, true},
		// весь алфавит nix-base32 (без e/o/t/u)
		{"0123456789abcdfghijklmnpqrsvwxyz", true},
		{"ffffffffffffffffffffffffffffffff", true},
		// hex с 'e' — НЕ валидный nix-base32 (реальный кейс из аудита)
		{"0123456789abcdef0123456789abcdef", false},
		{"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", false},
		// 31 символ
		{narHash32[:31], false},
		// 33 символа
		{narHash32 + "x", false},
		// заглавные — nix-base32 lowercase
		{"X0VM1MKFNQRQ3HXJCP2WSZ5L8H4CGD9Y", false},
		// буквы вне алфавита (e, o, t, u)
		{"ghoiklmnpqrstuoghijklmnopqrstug", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isNixBase32(c.s); got != c.want {
			t.Errorf("isNixBase32(%q) = %v, хочу %v", c.s, got, c.want)
		}
	}
}

func TestValidNarName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{narFileHash52 + ".nar.xz", true},
		{narFileHash52 + ".nar", true},
		// не nar-суффикс
		{narFileHash52 + ".nar.gz", false},
		{narFileHash52 + ".txt", false},
		// не 52-символьный fileHash
		{"foo.nar.xz", false},
		{narFileHash52[:51] + ".nar.xz", false}, // 51
		{narFileHash52 + "x.nar.xz", false},     // 53
		// 32-символьный nar — хеш store path, а не fileHash: nar
		// именуется по sha256 сжатого файла (52), не по пути
		{narHash32 + ".nar.xz", false},
		{narHash32 + ".nar", false},
		// hex с 'e' — не nix-base32
		{"0123456789abcdef0123456789abcdef0123456789abcdef01234567.nar.xz", false},
		// заглавные
		{strings.ToUpper(narFileHash52) + ".nar.xz", false},
		{"", false},
	}
	for _, c := range cases {
		if got := validNarName(c.name); got != c.want {
			t.Errorf("validNarName(%q) = %v, хочу %v", c.name, got, c.want)
		}
	}
}

func TestWantNar(t *testing.T) {
	cases := []struct {
		name string
		n    *Narinfo
		want string
	}{
		{"nar.xz валиден", &Narinfo{URL: "nar/" + narFileHash52 + ".nar.xz"}, "/nar/" + narFileHash52 + ".nar.xz"},
		{"nar несжатый", &Narinfo{URL: "nar/" + narFileHash52 + ".nar"}, "/nar/" + narFileHash52 + ".nar"},
		{"с ведущим «/»", &Narinfo{URL: "/nar/" + narFileHash52 + ".nar.xz"}, "/nar/" + narFileHash52 + ".nar.xz"},
		{"URL отсутствует", &Narinfo{}, ""},
		{"пустой URL", &Narinfo{URL: ""}, ""},
		{"nil narinfo", nil, ""},
		{"чужой префикс", &Narinfo{URL: "pool/" + narFileHash52 + ".nar.xz"}, ""},
		{"без префикса nar/", &Narinfo{URL: narFileHash52 + ".nar.xz"}, ""},
		{"невалидный хеш", &Narinfo{URL: "nar/foo.nar.xz"}, ""},
		{"не-nix-base32 ('e' в hex)", &Narinfo{URL: "nar/" + strings.Repeat("e", 52) + ".nar"}, ""},
		// 32-символьный nar — не fileHash: инверсия старого контракта
		{"32-символьный nar", &Narinfo{URL: "nar/" + narHash32 + ".nar.xz"}, ""},
		{"nar.gz не поддерживается", &Narinfo{URL: "nar/" + narFileHash52 + ".nar.gz"}, ""},
		{"лишний путь", &Narinfo{URL: "nar/sub/" + narFileHash52 + ".nar.xz"}, ""},
	}
	for _, c := range cases {
		if got := WantNar(c.n); got != c.want {
			t.Errorf("WantNar(%q) = %q, хочу %q", c.name, got, c.want)
		}
	}
}

func TestWantNarFromGolden(t *testing.T) {
	// end-to-end: golden narinfo → WantNar → nar-путь (как Enumerate
	// будущих сессий будет доставать пакет для префетча).
	data := mustReadTestdata(t, "narinfo.golden")
	n, err := ParseNarinfo(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseNarinfo: %v", err)
	}
	got := WantNar(n)
	want := "/nar/" + narFileHash52 + ".nar.xz"
	if got != want {
		t.Errorf("WantNar(golden) = %q, хочу %q", got, want)
	}
}

// narinfoEqual — глубокое сравнение (References — срез). Без reflect
// для читаемости.
func narinfoEqual(a, b *Narinfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.StorePath != b.StorePath || a.URL != b.URL || a.Compression != b.Compression ||
		a.FileHash != b.FileHash || a.FileSize != b.FileSize || a.NarHash != b.NarHash ||
		a.NarSize != b.NarSize || a.Deriver != b.Deriver || a.Sig != b.Sig || a.System != b.System {
		return false
	}
	if len(a.References) != len(b.References) {
		return false
	}
	for i := range a.References {
		if a.References[i] != b.References[i] {
			return false
		}
	}
	return true
}

// errReader отдаёт data, затем ошибку err.
type errReader struct {
	data []byte
	err  error
	pos  int
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// sameErr сравнивает ошибки мягко (для детерминизм-проверок фаззинга).
func sameErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return errors.Is(a, b) || errors.Is(b, a) || a.Error() == b.Error()
}
