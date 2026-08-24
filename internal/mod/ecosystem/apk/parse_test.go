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

package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"khrazhevnik/internal/core/domain"
)

// tarEntries — map «путь в tar» → содержимое файла; хелпер для сборки
// tar-архива из map (детерминированный, удобный для тестов).
type tarEntries map[string][]byte

// newTar собирает несжатый tar из map «путь → байты».
func newTar(t *testing.T, entries tarEntries) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newTarGz собирает gzip-сжатый tar из map (формат apk APKINDEX.tar.gz).
func newTarGz(t *testing.T, entries tarEntries) []byte {
	t.Helper()
	raw := newTar(t, entries)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// mustReadTestdata читает файл из testdata/.
func mustReadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("чтение testdata/%s: %v", name, err)
	}
	return b
}

// fakeMeta — MetaFetcher, отдающий предзагруженные байты по пути.
type fakeMeta struct {
	files map[string][]byte
}

func (m fakeMeta) Fetch(_ context.Context, ecosystemPath string) (io.ReadCloser, error) {
	b, ok := m.files[ecosystemPath]
	if !ok {
		return nil, &domain.NotFoundError{What: "upstream метаданные", Key: ecosystemPath}
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// collectIndex вытягивает итератор ParseAPKINDEX в срез.
func collectIndex(it func(yield func(*IndexEntry, error) bool)) ([]*IndexEntry, error) {
	var out []*IndexEntry
	var lastErr error
	for entry, err := range it {
		if err != nil {
			lastErr = err
			break
		}
		out = append(out, entry)
	}
	return out, lastErr
}

func TestParseAPKINDEXGolden(t *testing.T) {
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	db := newTarGz(t, tarEntries{
		"APKINDEX": indexText,
	})
	entries, err := collectIndex(ParseAPKINDEX(bytes.NewReader(db)))
	if err != nil {
		t.Fatalf("ParseAPKINDEX: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(entries))
	}
	if entries[0].FilePath != "x86_64/apk-example-1.0-r0.apk" {
		t.Errorf("entries[0].FilePath = %q", entries[0].FilePath)
	}
	if entries[0].Name != "apk-example" {
		t.Errorf("entries[0].Name = %q", entries[0].Name)
	}
	if entries[0].Version != "1.0-r0" {
		t.Errorf("entries[0].Version = %q", entries[0].Version)
	}
	if entries[1].FilePath != "x86_64/second-pkg-2.0-r1.apk" {
		t.Errorf("entries[1].FilePath = %q", entries[1].FilePath)
	}
}

func TestParseAPKINDEXTarGolden(t *testing.T) {
	// Точка входа ParseAPKINDEXTar без gzip — для фаззинга и прямых
	// тестов tar-парсера.
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	raw := newTar(t, tarEntries{
		"APKINDEX": indexText,
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(entries))
	}
	if entries[0].FilePath != "x86_64/apk-example-1.0-r0.apk" {
		t.Errorf("FilePath = %q", entries[0].FilePath)
	}
}

func TestParseAPKINDEXSkipsNonAPKINDEXFiles(t *testing.T) {
	// tar с посторонним файлом — парсер его пропускает, читает APKINDEX.
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	raw := newTar(t, tarEntries{
		"README":   []byte("this is not APKINDEX\n"),
		"APKINDEX": indexText,
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2 (APKINDEX прочитан)", len(entries))
	}
}

func TestParseAPKINDEXEmpty(t *testing.T) {
	// пустой tar (без APKINDEX) — пустой результат, не ошибка.
	raw := newTar(t, tarEntries{})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar пустой: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("пустой tar дал %d записей, хочу 0", len(entries))
	}
}

func TestParseAPKINDEXEmptyText(t *testing.T) {
	// tar с пустым APKINDEX — пустой результат, не ошибка.
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte(""),
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar пустой текст: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("пустой APKINDEX дал %d записей, хочу 0", len(entries))
	}
}

func TestParseAPKINDEXBadGzip(t *testing.T) {
	// мусор вместо gzip-потока — ErrBadGzip.
	_, err := collectIndex(ParseAPKINDEX(bytes.NewReader([]byte("not a gzip stream"))))
	if !errors.Is(err, ErrBadGzip) {
		t.Fatalf("ожидалась ErrBadGzip, получено %v", err)
	}
}

func TestParseAPKINDEXBadTar(t *testing.T) {
	// валидный gzip, но содержимое — не tar. gzip разжимает, tar.NewReader
	// ловит ошибку формата.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("not a tar archive at all, just some bytes"))
	_ = gw.Close()
	_, err := collectIndex(ParseAPKINDEX(bytes.NewReader(buf.Bytes())))
	if err == nil {
		t.Fatal("ожидалась ошибка битого tar, получено nil")
	}
}

func TestParseAPKINDEXEntryWithoutFilepath(t *testing.T) {
	// запись без F: — пустой FilePath (Enumerate отфильтрует).
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte("P:foo\nV:1.0-r0\n\nP:bar\nV:2.0-r1\nF:bar-2.0-r1.apk\n\n"),
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(entries))
	}
	if entries[0].FilePath != "" {
		t.Errorf("entries[0].FilePath = %q, хочу пусто", entries[0].FilePath)
	}
	if entries[0].Name != "foo" {
		t.Errorf("entries[0].Name = %q, хочу foo", entries[0].Name)
	}
	if entries[1].FilePath != "bar-2.0-r1.apk" {
		t.Errorf("entries[1].FilePath = %q", entries[1].FilePath)
	}
}

func TestParseAPKINDEXMultipleFields(t *testing.T) {
	// несколько полей в записи; парсер берёт первое F: (если дубль —
	// игнорирует второй, как и для P:/V:).
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte(
			"P:foo\nV:1.0-r0\nF:foo-1.0-r0.apk\nP:dup\nF:dup.apk\n\n"),
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].Name != "foo" {
		t.Errorf("Name = %q (первое P: должно выиграть)", entries[0].Name)
	}
	if entries[0].FilePath != "foo-1.0-r0.apk" {
		t.Errorf("FilePath = %q (первое F: должно выиграть)", entries[0].FilePath)
	}
}

func TestParseAPKINDEXLineWithoutColon(t *testing.T) {
	// строка без «:» — tolerant: игнорируется, парсер не падает.
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte("P:foo\nthis line has no colon\nV:1.0-r0\nF:foo.apk\n\n"),
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].Name != "foo" || entries[0].Version != "1.0-r0" {
		t.Errorf("entry = %+v (no-colon line не должна ломать)", entries[0])
	}
}

func TestParseAPKINDEXTooManyEntries(t *testing.T) {
	// потолок числа записей: маленький лимит, на (lim+1)-й — ошибка.
	const lim = 3
	var b strings.Builder
	for i := 0; i < lim+1; i++ {
		b.WriteString("P:p")
		b.WriteByte(byte('a' + i))
		b.WriteString("\nF:f")
		b.WriteByte(byte('a' + i))
		b.WriteString(".apk\n\n")
	}
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte(b.String()),
	})
	got, err := collectIndex(parseAPKINDEXTar(bytes.NewReader(raw), parseLimits{
		decompressed: maxDecompressedApk, entries: lim, fileSize: maxIndexFileSize, lines: maxIndexLines,
	}))
	if !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("ожидалась ErrTooManyEntries, получено %v (got=%d)", err, len(got))
	}
	if len(got) != lim {
		t.Errorf("отдано %d записей, хочу %d до ошибки", len(got), lim)
	}
}

func TestParseAPKINDEXIndexTooLarge(t *testing.T) {
	// файл APKINDEX длиннее лимита — ErrIndexTooLarge. Лимит стянут до 64 байт.
	big := bytes.Repeat([]byte("P:foo\n"), 20) // ~100 байт
	raw := newTar(t, tarEntries{
		"APKINDEX": big,
	})
	_, err := collectIndex(parseAPKINDEX(bytes.NewReader(newGz(t, raw)), parseLimits{
		decompressed: maxDecompressedApk, entries: maxIndexEntries, fileSize: 64, lines: maxIndexLines,
	}))
	if !errors.Is(err, ErrIndexTooLarge) {
		t.Fatalf("ожидалась ErrIndexTooLarge, получено %v", err)
	}
}

func TestParseAPKINDEXZipBombGuard(t *testing.T) {
	// gzip-файл, декомпресс-лимит 1KiB — разжатый поток превышает лимит
	// → ErrDecompressTooLarge. payload: APKINDEX > 1KiB.
	payload := bytes.Repeat([]byte("P:foo\nF:foo.apk\n\n"), 100) // ~1.4KiB
	raw := newTar(t, tarEntries{
		"APKINDEX": payload,
	})
	db := newGz(t, raw)
	_, err := collectIndex(parseAPKINDEX(bytes.NewReader(db), parseLimits{
		decompressed: 1024, entries: maxIndexEntries, fileSize: maxIndexFileSize, lines: maxIndexLines,
	}))
	if !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ожидалась ErrDecompressTooLarge, получено %v", err)
	}
}

func TestParseAPKINDEXDeterminism(t *testing.T) {
	// повторный разбор того же потока обязан дать идентичный результат.
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	db := newTarGz(t, tarEntries{
		"APKINDEX": indexText,
	})
	first, firstErr := collectIndex(ParseAPKINDEX(bytes.NewReader(db)))
	second, secondErr := collectIndex(ParseAPKINDEX(bytes.NewReader(db)))
	if !sameErr(firstErr, secondErr) {
		t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
	}
	if len(first) != len(second) {
		t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].FilePath != second[i].FilePath || first[i].Name != second[i].Name {
			t.Fatalf("запись %d differs между прогонами", i)
		}
	}
}

func TestParseAPKINDEXTarOnGarbage(t *testing.T) {
	// произвольный мусор как tar-поток — не паника, ошибка или пустой.
	_, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader([]byte("garbage"))))
	_ = err
}

func TestParseAPKINDEXTarFirstNonAPKINDEXThenAPKINDEX(t *testing.T) {
	// tar с посторонним файлом первым, APKINDEX вторым — парсер
	// пропускает посторонние и читает APKINDEX.
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	raw := newTar(t, tarEntries{
		"README":             []byte("not apkindex\n"),
		"subdir/DESCRIPTION": []byte("also not apkindex\n"),
		"APKINDEX":           indexText,
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2 (APKINDEX найден после посторонних)", len(entries))
	}
}

func TestParseAPKINDEXTextTooManyLines(t *testing.T) {
	// потолок числа строк в одном APKINDEX: маленький лимит, превышение
	// → ErrIndexTooLarge. payload: много строк без разделителя записей.
	big := bytes.Repeat([]byte("P:foo\n"), 200) // 200 строк
	raw := newTar(t, tarEntries{
		"APKINDEX": big,
	})
	_, err := collectIndex(parseAPKINDEXTar(bytes.NewReader(raw), parseLimits{
		decompressed: maxDecompressedApk, entries: maxIndexEntries, fileSize: maxIndexFileSize, lines: 64,
	}))
	if !errors.Is(err, ErrIndexTooLarge) {
		t.Fatalf("ожидалась ErrIndexTooLarge (lines), получено %v", err)
	}
}

func TestParseAPKINDEXTextReaderError(t *testing.T) {
	// ридер, падающий посреди APKINDEX — ошибка прокидывается.
	r := &errReader{data: []byte("P:foo\nF:foo.apk\n"), err: io.ErrUnexpectedEOF}
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte("placeholder"),
	})
	_ = raw
	// передаём errReader напрямую в parseAPKINDEXText через обёртку:
	// tar здесь не нужен, тестируем текстовый парсер изоляированно.
	_, err := collectIndex(parseAPKINDEXText(r, parseLimits{
		decompressed: maxDecompressedApk, entries: maxIndexEntries, fileSize: maxIndexFileSize, lines: maxIndexLines,
	}))
	if err == nil {
		t.Fatal("ожидалась прокиданная ошибка ридера, получено nil")
	}
}

func TestParseAPKINDEXGzipReaderError(t *testing.T) {
	// gzip-поток обрывается посреди — gzip.Reader.Read отдаёт ошибку,
	// parseAPKINDEX прокидывает её. Используем усечённый gzip.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("some payload that will be truncated"))
	_ = gw.Close()
	// усекаем gzip-поток — декомпрессия упадёт.
	truncated := buf.Bytes()[:len(buf.Bytes())/2]
	_, err := collectIndex(ParseAPKINDEX(bytes.NewReader(truncated)))
	if err == nil {
		t.Fatal("ожидалась ошибка усеченного gzip, получено nil")
	}
}

func TestParseAPKINDEXTarTarReaderError(t *testing.T) {
	// ридер, падающий посреди tar — tar.NewReader прокидывает ошибку.
	r := &errReader{data: []byte("garbage tar header"), err: io.ErrUnexpectedEOF}
	_, err := collectIndex(ParseAPKINDEXTar(r))
	if err == nil {
		t.Fatal("ожидалась прокиданная ошибка tar, получено nil")
	}
}

func TestParseAPKINDEXTarApkindexInSubdir(t *testing.T) {
	// APKINDEX в подкаталоге — isAPKINDEXName терпим к префиксу.
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	raw := newTar(t, tarEntries{
		"meta/APKINDEX": indexText,
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2 (APKINDEX в подкаталоге)", len(entries))
	}
}

func TestParseAPKINDEXTextLastLineNoNewline(t *testing.T) {
	// последняя строка без \n — всё равно отдаётся (tolerant).
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte("P:foo\nV:1.0\nF:foo.apk"),
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].FilePath != "foo.apk" {
		t.Errorf("FilePath = %q", entries[0].FilePath)
	}
}

func TestParseAPKINDEXTextCRLF(t *testing.T) {
	// CRLF-окончания — \r срезается, парсер не ломается.
	raw := newTar(t, tarEntries{
		"APKINDEX": []byte("P:foo\r\nV:1.0\r\nF:foo.apk\r\n\r\n"),
	})
	entries, err := collectIndex(ParseAPKINDEXTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseAPKINDEXTar CRLF: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].Name != "foo" || entries[0].FilePath != "foo.apk" {
		t.Errorf("entry = %+v (\\r не срезан?)", entries[0])
	}
}

func TestIsAPKINDEXName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"APKINDEX", true},
		{"subdir/APKINDEX", true},
		{"APKINDEX.tar.gz", false},
		{"README", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isAPKINDEXName(c.name); got != c.want {
			t.Errorf("isAPKINDEXName(%q) = %v, хочу %v", c.name, got, c.want)
		}
	}
}

func sameErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return errors.Is(a, b) || errors.Is(b, a) || a.Error() == b.Error()
}

// newGz gzip-упаковывает b для теста.
func newGz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
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
