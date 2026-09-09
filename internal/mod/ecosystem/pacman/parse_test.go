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

package pacman

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
)

// tarEntries — map «путь в tar» → содержимое файла; хелпер для сборки
// tar-архива из map (детерминированный, удобный для тестов).
type tarEntries map[string][]byte

// newTar собирает несжатый tar из map «путь → байты». Каталоги создаются
// автоматически по путям файлов. Имена сортируются — порядок записей
// детерминирован (иначе map-рандомизация ломает тесты, утверждающие
// порядок, как TestParseDBGolden).
func newTar(t *testing.T, entries tarEntries) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := entries[name]
		// запись каталога
		dir := name
		if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
			dir = name[:idx+1]
		}
		if dir != "" && dir != name {
			if err := tw.WriteHeader(&tar.Header{
				Name:     dir,
				Typeflag: tar.TypeDir,
				Mode:     0o755,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(content)),
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

// newTarZst собирает zstd-сжатый tar из map (формат pacman .db).
func newTarZst(t *testing.T, entries tarEntries) []byte {
	t.Helper()
	raw := newTar(t, entries)
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newTarGz собирает gzip-сжатый tar из map (sync-БД Arch публикует
// {repo}.db как tar.gz). Дубль apk-хелпера легален: mod→mod запрещён,
// тесты самодостаточны.
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

// collectDB вытягивает итератор ParseDB в срез; для asserting-тестов.
func collectDB(it func(yield func(*DescEntry, error) bool)) ([]*DescEntry, error) {
	var out []*DescEntry
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

func TestParseDBGolden(t *testing.T) {
	desc1 := mustReadTestdata(t, "desc-1.golden")
	desc2 := mustReadTestdata(t, "desc-2.golden")
	db := newTarZst(t, tarEntries{
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	})
	entries, err := collectDB(ParseDB(bytes.NewReader(db)))
	if err != nil {
		t.Fatalf("ParseDB: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(entries))
	}
	if entries[0].Filename != "pacman-example-1.0-1-x86_64.pkg.tar.zst" {
		t.Errorf("entries[0].Filename = %q", entries[0].Filename)
	}
	if entries[0].Name != "pacman-example" {
		t.Errorf("entries[0].Name = %q", entries[0].Name)
	}
	if entries[0].Version != "1.0-1" {
		t.Errorf("entries[0].Version = %q", entries[0].Version)
	}
	if entries[1].Filename != "second-pkg-2.0-1-any.pkg.tar.xz" {
		t.Errorf("entries[1].Filename = %q", entries[1].Filename)
	}
}

func TestParseDBGzipGolden(t *testing.T) {
	// gzip-ветка (sync-БД Arch — core.db это tar.gz): те же entries,
	// что у zstd-golden — те же desc-результаты (детект по magic-байтам,
	// не по расширению).
	desc1 := mustReadTestdata(t, "desc-1.golden")
	desc2 := mustReadTestdata(t, "desc-2.golden")
	db := newTarGz(t, tarEntries{
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	})
	entries, err := collectDB(ParseDB(bytes.NewReader(db)))
	if err != nil {
		t.Fatalf("ParseDB gzip: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("записей = %d, хочу 2", len(entries))
	}
	if entries[0].Filename != "pacman-example-1.0-1-x86_64.pkg.tar.zst" {
		t.Errorf("entries[0].Filename = %q", entries[0].Filename)
	}
	if entries[0].Name != "pacman-example" {
		t.Errorf("entries[0].Name = %q", entries[0].Name)
	}
	if entries[0].Version != "1.0-1" {
		t.Errorf("entries[0].Version = %q", entries[0].Version)
	}
	if entries[1].Filename != "second-pkg-2.0-1-any.pkg.tar.xz" {
		t.Errorf("entries[1].Filename = %q", entries[1].Filename)
	}
}

func TestParseDBAutoDetect(t *testing.T) {
	// детект по magic, не по расширению: поток без имени файла —
	// gzip и zstd оба разбираются одной точкой входа.
	desc := mustReadTestdata(t, "desc-1.golden")
	for _, tc := range []struct {
		name string
		db   []byte
	}{
		{"gzip", newTarGz(t, tarEntries{"foo-1.0-1-x86_64/desc": desc})},
		{"zstd", newTarZst(t, tarEntries{"foo-1.0-1-x86_64/desc": desc})},
	} {
		entries, err := collectDB(ParseDB(bytes.NewReader(tc.db)))
		if err != nil {
			t.Fatalf("%s: ParseDB: %v", tc.name, err)
		}
		if len(entries) != 1 {
			t.Fatalf("%s: записей = %d, хочу 1", tc.name, len(entries))
		}
		if entries[0].Name != "pacman-example" {
			t.Errorf("%s: Name = %q, хочу pacman-example", tc.name, entries[0].Name)
		}
	}
	// короткий поток (<4 байт) — не паника; ошибка или пустой результат
	// допустимы (детект честно уходит в одну из веток).
	for _, short := range [][]byte{nil, {0x1F}, {0x28, 0xB5}, {0x1F, 0x8B}} {
		_, _ = collectDB(ParseDB(bytes.NewReader(short)))
	}
}

func TestParseDBTarGolden(t *testing.T) {
	// Точка входа parseDBTar без zstd — для фаззинга и прямых тестов
	// tar-парсера.
	desc1 := mustReadTestdata(t, "desc-1.golden")
	raw := newTar(t, tarEntries{
		"foo-1.0-1-x86_64/desc": desc1,
	})
	entries, err := collectDB(ParseDBTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseDBTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].Filename != "pacman-example-1.0-1-x86_64.pkg.tar.zst" {
		t.Errorf("Filename = %q", entries[0].Filename)
	}
}

func TestParseDBSkipsNonDescFiles(t *testing.T) {
	desc := mustReadTestdata(t, "desc-1.golden")
	raw := newTar(t, tarEntries{
		"foo-1.0-1-x86_64/desc":    desc,
		"foo-1.0-1-x86_64/files":   []byte("%FILES%\n/usr/bin/foo\n"),
		"foo-1.0-1-x86_64/depends": []byte("%DEPENDS%\nlibc\n"),
	})
	entries, err := collectDB(ParseDBTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseDBTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1 (только desc)", len(entries))
	}
}

func TestParseDBEmpty(t *testing.T) {
	// пустой tar — пустой результат, не ошибка.
	raw := newTar(t, tarEntries{})
	entries, err := collectDB(ParseDBTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseDBTar пустой: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("пустой tar дал %d записей, хочу 0", len(entries))
	}
}

func TestParseDBBadZstd(t *testing.T) {
	// мусор вместо zstd-потока — ошибка (ErrBadZstd или битый tar,
	// зависит от того, когда zstd-декодер спохватится; главное — не
	// паника и детерминизм). zstd.NewReader ленив: на мусоре может
	// отдать nil-ошибку, а первая Read упадёт — в обоих случаях parseDB
	// обязан вернуть ошибку наружу.
	_, err := collectDB(ParseDB(bytes.NewReader([]byte("not a zstd stream"))))
	if err == nil {
		t.Fatal("ожидалась ошибка битого zstd, получено nil")
	}
}

func TestParseDBBadTar(t *testing.T) {
	// валидный zstd, но содержимое — не tar. zstd разжимает, tar.NewReader
	// ловит ошибку формата.
	zw, _ := zstd.NewWriter(io.Discard)
	var buf bytes.Buffer
	zw.Reset(&buf)
	_, _ = zw.Write([]byte("not a tar archive at all, just some bytes"))
	_ = zw.Close()
	_, err := collectDB(ParseDB(bytes.NewReader(buf.Bytes())))
	if err == nil {
		t.Fatal("ожидалась ошибка битого tar, получено nil")
	}
}

func TestParseDBDescWithoutFilename(t *testing.T) {
	// desc без %FILENAME% — пустой Filename (Enumerate отфильтрует).
	raw := newTar(t, tarEntries{
		"foo-1.0-1-x86_64/desc": []byte("%NAME%\nfoo\n%VERSION%\n1.0-1\n"),
	})
	entries, err := collectDB(ParseDBTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseDBTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].Filename != "" {
		t.Errorf("Filename = %q, хочу пусто", entries[0].Filename)
	}
	if entries[0].Name != "foo" {
		t.Errorf("Name = %q, хочу foo", entries[0].Name)
	}
}

func TestParseDBDescMultilineField(t *testing.T) {
	// многострочное поле %DEPENDS% — не ломает парсер, следующие поля
	// читаются корректно.
	raw := newTar(t, tarEntries{
		"foo-1.0-1-x86_64/desc": []byte(
			"%FILENAME%\nfoo-1.0-1-x86_64.pkg.tar.zst\n" +
				"%NAME%\nfoo\n" +
				"%DEPENDS%\nglibc\nzstd\nzlib\n" +
				"%VERSION%\n1.0-1\n"),
	})
	entries, err := collectDB(ParseDBTar(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseDBTar: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("записей = %d, хочу 1", len(entries))
	}
	if entries[0].Filename != "foo-1.0-1-x86_64.pkg.tar.zst" {
		t.Errorf("Filename = %q", entries[0].Filename)
	}
	if entries[0].Version != "1.0-1" {
		t.Errorf("Version = %q (после многострочного DEPENDS)", entries[0].Version)
	}
}

func TestParseDBTooManyEntries(t *testing.T) {
	// потолок числа desc-записей: маленький лимит, на (lim+1)-й — ошибка.
	const lim = 3
	desc := []byte("%FILENAME%\nf.pkg.tar.zst\n")
	entries := tarEntries{}
	for i := 0; i < lim+1; i++ {
		entries[string(rune('a'+i))+"-1.0-1-x86_64/desc"] = desc
	}
	raw := newTar(t, entries)
	got, err := collectDB(parseDBTar(bytes.NewReader(raw), parseLimits{
		decompressed: maxDecompressed, entries: lim, descSize: maxDescSize, descLines: maxDescLines,
	}))
	if !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("ожидалась ErrTooManyEntries, получено %v (got=%d)", err, len(got))
	}
	if len(got) != lim {
		t.Errorf("отдано %d записей, хочу %d до ошибки", len(got), lim)
	}
}

func TestParseDBDescTooLarge(t *testing.T) {
	// desc длиннее лимита — ErrDescTooLarge. Лимит стянут до 64 байт.
	big := bytes.Repeat([]byte("x"), 65)
	raw := newTar(t, tarEntries{
		"foo-1.0-1-x86_64/desc": append([]byte("%NAME%\n"), big...),
	})
	_, err := collectDB(parseDBTar(bytes.NewReader(raw), parseLimits{
		decompressed: maxDecompressed, entries: maxDescEntries, descSize: 64, descLines: maxDescLines,
	}))
	if !errors.Is(err, ErrDescTooLarge) {
		t.Fatalf("ожидалась ErrDescTooLarge, получено %v", err)
	}
}

func TestParseDBZipBombGuard(t *testing.T) {
	// zst-файл, декомпресс-лимит 1KiB — разжатый поток превышает лимит
	// → ErrDecompressTooLarge. payload: tar с одним desc > 1KiB.
	desc := bytes.Repeat([]byte("%NAME%\nfoo\n"), 200) // ~1.6KiB
	raw := newTar(t, tarEntries{
		"foo-1.0-1-x86_64/desc": desc,
	})
	db := newTarZst(t, tarEntries{
		"foo-1.0-1-x86_64/desc": desc,
	})
	_, err := collectDB(parseDB(bytes.NewReader(db), parseLimits{
		decompressed: 1024, entries: maxDescEntries, descSize: maxDescSize, descLines: maxDescLines,
	}))
	if !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ожидалась ErrDecompressTooLarge, получено %v", err)
	}
	// размер исходного tar проверяем для документации (payload > лимита)
	if len(raw) <= 1024 {
		t.Errorf("payload %d байт должен быть > 1024 для теста лимита", len(raw))
	}
}

func TestParseDBGzipBombGuard(t *testing.T) {
	// настоящая gzip-бомба: 1100 desc-записей по ~1MiB — распакованный
	// поток > 1GiB (кап maxDecompressed), сжатый файл — килобайты
	// (повторы). Чтение стримингом: итератор гаснет на ошибке, никакого
	// ReadAll распакованной бомбы (OOM-урок 77). Content каждой desc —
	// строго меньше descSize-потолка, чтобы помеха проверяла именно
	// декомпресс-лимит, а не ErrDescTooLarge.
	block := bytes.Repeat([]byte("x"), (1<<20)-(1<<10)) // 1MiB-1KiB
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(gw)
	for i := 0; i < 1100; i++ {
		name := fmt.Sprintf("pkg-%04d-1.0-1-x86_64/desc", i)
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(block)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	bomb := buf.Bytes()

	_, err = collectDB(ParseDB(bytes.NewReader(bomb)))
	if !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ожидалась ErrDecompressTooLarge, получено %v", err)
	}

	// Для gzip счётчик limitedReader честен (δ-нечестность — только
	// zstd, урок 77): через ту же точку детекта с маленьким капом
	// проверяем, что декомпрессор отдал не больше капа + один чанк.
	src, closeFn, err := newDBStream(bytes.NewReader(bomb))
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	cr := &countingReader{r: src}
	_, _ = collectDB(parseDBTar(&limitedReader{r: cr, limit: 1 << 20, sentinel: errDecompressLimit}, parseLimits{
		decompressed: maxDecompressed, entries: maxDescEntries, descSize: maxDescSize, descLines: maxDescLines,
	}))
	const delta = 8192 // один чанк tar/readDesc поверх точного капа
	if cr.n > (1<<20)+delta {
		t.Errorf("gzip-декомпрессор отдал %d байт, хочу ≤ %d (кап+δ)", cr.n, (1<<20)+delta)
	}
}

func TestParseDBTarOnGarbage(t *testing.T) {
	// произвольный мусор как tar-поток — не паника, ошибка или пустой.
	_, err := collectDB(ParseDBTar(bytes.NewReader([]byte("garbage"))))
	// tar.NewReader на мусоре обычно отдаёт ошибку; пустой результат
	// тоже допустим (зависит от реализации). Главное — без паники.
	_ = err
}

func TestParseDBDeterminism(t *testing.T) {
	// повторный разбор того же потока обязан дать идентичный результат.
	desc1 := mustReadTestdata(t, "desc-1.golden")
	desc2 := mustReadTestdata(t, "desc-2.golden")
	db := newTarZst(t, tarEntries{
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	})
	first, firstErr := collectDB(ParseDB(bytes.NewReader(db)))
	second, secondErr := collectDB(ParseDB(bytes.NewReader(db)))
	if !sameErr(firstErr, secondErr) {
		t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
	}
	if len(first) != len(second) {
		t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Filename != second[i].Filename || first[i].Name != second[i].Name {
			t.Fatalf("запись %d differs между прогонами", i)
		}
	}
}

// countingReader считает байты, проходящие через него (ассерт «кап+δ»
// на gzip-ветке бомбы).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func sameErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return errors.Is(a, b) || errors.Is(b, a) || a.Error() == b.Error()
}
