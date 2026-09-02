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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readAll собирает записи итератора в срез; для asserting-тестов
// удобнее срез, чем pull-based обход.
func readAll(t *testing.T, r io.Reader) []*Stanza {
	t.Helper()
	var out []*Stanza
	for s, err := range Stanzas(r) {
		if err != nil {
			t.Fatalf("Stanzas: %v", err)
		}
		out = append(out, s)
	}
	return out
}

// readAllErr как readAll, но ожидает ровно одну ошибку в конце.
func readAllErr(t *testing.T, r io.Reader) ([]*Stanza, error) {
	t.Helper()
	var out []*Stanza
	var lastErr error
	for s, err := range Stanzas(r) {
		if err != nil {
			lastErr = err
			break
		}
		out = append(out, s)
	}
	return out, lastErr
}

func mustOpen(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("открытие testdata/%s: %v", name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestStanzasPackages(t *testing.T) {
	stanzas := readAll(t, mustOpen(t, "Packages.golden"))
	if len(stanzas) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(stanzas))
	}
	first := stanzas[0]
	if first.Get("Package") != "apt-example" {
		t.Errorf("Package = %q", first.Get("Package"))
	}
	if first.Get("Version") != "1.0-1" {
		t.Errorf("Version = %q", first.Get("Version"))
	}
	if first.Get("Architecture") != "amd64" {
		t.Errorf("Architecture = %q", first.Get("Architecture"))
	}
	// Description: первая строка + 19 продолжений, склеенных \n.
	desc := first.Get("Description")
	lines := strings.Split(desc, "\n")
	if len(lines) != 20 {
		t.Fatalf("Description: %d строк, хочу 20 (1 + 19); значение=%q", len(lines), desc)
	}
	if lines[0] != "Example package for tests" {
		t.Errorf("Description[0] = %q", lines[0])
	}
	if lines[1] != "This is line 1 of the long description." {
		t.Errorf("Description[1] = %q", lines[1])
	}
	if lines[19] != "This is line 19 of the long description." {
		t.Errorf("Description[19] = %q", lines[19])
	}
	// порядок ключей: Package первая, Description последняя (как в файле)
	keys := first.Keys()
	if keys[0] != "Package" {
		t.Errorf("Keys[0] = %q, хочу Package", keys[0])
	}
	if keys[len(keys)-1] != "Description" {
		t.Errorf("Keys[-1] = %q, хочу Description", keys[len(keys)-1])
	}
	// вторая запись
	second := stanzas[1]
	if second.Get("Package") != "second-pkg" {
		t.Errorf("вторая Package = %q", second.Get("Package"))
	}
	if second.Get("Description") != "short second\ncontinuation here" {
		t.Errorf("вторая Description = %q", second.Get("Description"))
	}
}

func TestStanzasRelease(t *testing.T) {
	stanzas := readAll(t, mustOpen(t, "Release.golden"))
	if len(stanzas) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(stanzas))
	}
	r := stanzas[0]
	if r.Get("Origin") != "Debian" {
		t.Errorf("Origin = %q", r.Get("Origin"))
	}
	if r.Get("Suite") != "stable" {
		t.Errorf("Suite = %q", r.Get("Suite"))
	}
	// многострочное Description со склейкой через \n
	desc := r.Get("Description")
	if !strings.Contains(desc, "release description\nspanning multiple lines") {
		t.Errorf("Description не склеен: %q", desc)
	}
	// MD5sum — многострочное поле со списком чексумм
	md5 := r.Get("MD5sum")
	if !strings.Contains(md5, "123456 Release") || !strings.Contains(md5, "654321 main/binary-amd64/Packages") {
		t.Errorf("MD5sum не разобран: %q", md5)
	}
}

func TestStanzasEmpty(t *testing.T) {
	stanzas := readAll(t, mustOpen(t, "empty.golden"))
	if len(stanzas) != 0 {
		t.Fatalf("пустой файл дал %d записей, хочу 0", len(stanzas))
	}
}

func TestStanzasCRLF(t *testing.T) {
	// CRLF-окончания строк должны срезаться: парсер не должен
	// оставлять \r в значениях или ломать fold.
	input := []byte("Package: crlf-pkg\r\nVersion: 1.0\r\nDescription: short\r\n long line\r\n\r\n")
	stanzas := readAll(t, bytes.NewReader(input))
	if len(stanzas) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(stanzas))
	}
	s := stanzas[0]
	if s.Get("Package") != "crlf-pkg" {
		t.Errorf("Package = %q (хочу без \\r)", s.Get("Package"))
	}
	if s.Get("Version") != "1.0" {
		t.Errorf("Version = %q", s.Get("Version"))
	}
	if got := s.Get("Description"); got != "short\nlong line" {
		t.Errorf("Description = %q (хочу fold без \\r)", got)
	}
}

func TestStanzasBadUTF8(t *testing.T) {
	// Битый UTF-8 в значении сохраняется как raw bytes: Go-строка
	// держит произвольные байты. Поле должно читаться без паники и
	// без перекодирования.
	input := []byte("Package: bad-utf8\nDescription: \xff\xfe\n\n")
	stanzas, err := readAllErr(t, bytes.NewReader(input))
	if err != nil {
		t.Fatalf("парсер упал на битом UTF-8: %v", err)
	}
	if len(stanzas) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(stanzas))
	}
	desc := stanzas[0].Get("Description")
	if !strings.Contains(desc, "\xff\xfe") {
		t.Errorf("битый UTF-8 потерян: Description = %q", desc)
	}
}

func TestStanzasNoTrailingBlank(t *testing.T) {
	// запись без финальной пустой строки (нет \n\n) всё равно отдаётся
	input := []byte("Package: tailless\nVersion: 1.0")
	stanzas := readAll(t, bytes.NewReader(input))
	if len(stanzas) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(stanzas))
	}
	if stanzas[0].Get("Package") != "tailless" {
		t.Errorf("Package = %q", stanzas[0].Get("Package"))
	}
}

func TestStanzasMultipleBlanks(t *testing.T) {
	// подряд идущие пустые строки — не отдельные записи
	input := []byte("Package: a\n\n\n\nPackage: b\n\n")
	stanzas := readAll(t, bytes.NewReader(input))
	if len(stanzas) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(stanzas))
	}
}

func TestStanzasNoColon(t *testing.T) {
	// строка без «:» и не продолжение — структурный сбой: парсер
	// прерывает обход с ошибкой, не маскируя чужой формат под пустой.
	input := []byte("Package: ok\nthis line has no colon\n")
	_, err := readAllErr(t, bytes.NewReader(input))
	if !errors.Is(err, ErrNoColon) {
		t.Fatalf("ожидалась ErrNoColon, получено %v", err)
	}
}

func TestStanzasContinuationNoField(t *testing.T) {
	// продолжение до любого поля — tolerant: строка игнорируется,
	// парсер не падает (в отличие от no-colon это типичный мусор в
	// конце файла, а не структурная ошибка формата).
	input := []byte(" leading orphan line\nPackage: after\n\n")
	stanzas, err := readAllErr(t, bytes.NewReader(input))
	if err != nil {
		t.Fatalf("orphan continuation не должен валить парсер: %v", err)
	}
	if len(stanzas) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(stanzas))
	}
}

func TestStanzasFieldTooLong(t *testing.T) {
	// одно значение длиннее лимита — ошибка ErrFieldTooLong
	big := strings.Repeat("x", maxFieldValue+1)
	input := []byte("Package: " + big + "\n\n")
	_, err := readAllErr(t, bytes.NewReader(input))
	if !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("ожидалась ErrFieldTooLong, получено %v", err)
	}
}

func TestStanzasTotalBytesCap(t *testing.T) {
	// верификация 2026-09-02: число полей в записи по отдельности не
	// ограничено — бесконечные «A<n>: x» без пустой строки росли бы
	// картой неограниченно. Суммарный потолок field*stanzas (здесь
	// 8*4=32 байта) — ErrFieldTooLong на превышении. Маленькие лимиты,
	// как в TestStanzasTooMany: реальный потолок 1 ТиБ в тесте не
	// набрать и не нужно.
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("F0: vvvv\n")
	}
	var lastErr error
	for _, err := range stanzas(strings.NewReader(b.String()), limits{stanzas: 4, field: 8, name: 8}) {
		if err != nil {
			lastErr = err
			break
		}
	}
	if !errors.Is(lastErr, ErrFieldTooLong) {
		t.Fatalf("ожидалась ErrFieldTooLong, получено %v", lastErr)
	}
}

func TestStanzasTooMany(t *testing.T) {
	// потолок числа записей: маленький лимит, на (lim+1)-й записи
	// парсер отказывает. Реальный лимит — 1 млн; гонять его в тесте
	// бессмысленно, поэтому stanzasWithLimits с lim=4.
	const lim = 4
	var b strings.Builder
	for i := 0; i < lim+1; i++ {
		b.WriteString("Package: p\n\n")
	}
	var got []*Stanza
	var lastErr error
	for s, err := range stanzas(strings.NewReader(b.String()), limits{stanzas: lim, field: maxFieldValue, name: maxFieldName}) {
		if err != nil {
			lastErr = err
			break
		}
		got = append(got, s)
	}
	if len(got) != lim {
		t.Fatalf("отдано %d записей, хочу %d до ошибки", len(got), lim)
	}
	if !errors.Is(lastErr, ErrTooManyStanzas) {
		t.Fatalf("ожидалась ErrTooManyStanzas, получено %v", lastErr)
	}
}

func TestStanzaEqual(t *testing.T) {
	a := newStanza()
	a.Set("A", "1")
	a.Set("B", "2")
	b := newStanza()
	b.Set("B", "2")
	b.Set("A", "1") // другой порядок — Equal игнорирует
	if !a.Equal(b) {
		t.Error("Equal должен игнорировать порядок ключей")
	}
	b.Set("A", "x")
	if a.Equal(b) {
		t.Error("Equal не должен считать разными значения одинаковыми")
	}
	if a.Equal(nil) || (&Stanza{}).Equal(a) {
		t.Error("nil/разные размеры — не Equal")
	}
}

func TestStanzasReaderError(t *testing.T) {
	// ридер, падающий посреди потока, прокидывает ошибку
	r := &errReader{data: []byte("Package: ok\n"), err: io.ErrUnexpectedEOF}
	_, err := readAllErr(t, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ожидалась прокиданная ошибка ридера, получено %v", err)
	}
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

// countingReader считает прочитанные из r байты: OOM-тестам нужно
// доказать, что отказ наступает ДО полного прочтения потока.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestStanzasHugeLineNoNewline — аудит 2026-08-30: строка 2 MiB без
// \n. Раньше ReadString('\n') буферизовала её целиком ДО проверки
// лимита; теперь ErrFieldTooLong после ~лимита прочитанного —
// счётчик доказывает, что из потока взято существенно меньше
// полного размера (и не больше лимита строки + буфер bufio).
func TestStanzasHugeLineNoNewline(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 2<<20) // 2 MiB без \n
	cr := &countingReader{r: bytes.NewReader(data)}
	_, err := readAllErr(t, cr)
	if !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("ожидалась ErrFieldTooLong, получено %v", err)
	}
	if cr.n >= len(data) {
		t.Fatalf("прочитано %d из %d байт — отказ обязан наступать до полного прочтения", cr.n, len(data))
	}
	if want := maxFieldValue + maxFieldName + 2; cr.n > want+8192 {
		t.Errorf("прочитано %d байт, хочу не более ~%d (лимит строки + буфер bufio)", cr.n, want)
	}
}

// TestStanzasLineAtSliceBoundary — строка длиннее буфера bufio
// (4096), но короче лимита: куски склеиваются, содержимое не теряется
// и не дублируется (регрессия чанкового чтения в readLine).
func TestStanzasLineAtSliceBoundary(t *testing.T) {
	value := strings.Repeat("y", 8000) // > 4096, < лимита
	input := []byte("Description: " + value + "\n\n")
	stanzas, err := readAllErr(t, bytes.NewReader(input))
	if err != nil {
		t.Fatalf("строка 8000 байт не должна валить парсер: %v", err)
	}
	if len(stanzas) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(stanzas))
	}
	if got := stanzas[0].Get("Description"); got != value {
		t.Errorf("строка через границу буфера искажена: len=%d, хочу len=%d", len(got), len(value))
	}
}
