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
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseAPKINDEX гоняет парсер tar/текста на произвольных байтах,
// поданных как распакованный tar-поток (точка входа ParseAPKINDEXTar —
// без gzip, чтобы фаззер исследовал именно формат tar+текст, а не
// gzip-кодек). Инварианты: не паниковать, не зацикливаться (таймаут
// теста ловит), повторный разбор тех же байт даёт тот же набор записей
// (детерминизм). Потолки стянуты до маленьких значений.
func FuzzParseAPKINDEX(f *testing.F) {
	// Посев-корпус: золотые фикстуры (собранные в tar) + синтетика.
	seeds := [][]byte{
		[]byte(""),
		[]byte("garbage not a tar"),
		[]byte("P:foo\nV:1.0\nF:foo.apk\n\n"),
	}
	indexText, err := os.ReadFile(filepath.Clean("testdata/APKINDEX.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	goldenTar := func(entries map[string][]byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for name, content := range entries {
			_ = tw.WriteHeader(&tar.Header{
				Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)),
			})
			_, _ = tw.Write(content)
		}
		_ = tw.Close()
		return buf.Bytes()
	}
	seeds = append(seeds, goldenTar(map[string][]byte{
		"APKINDEX": indexText,
	}))
	seeds = append(seeds, goldenTar(map[string][]byte{
		"APKINDEX": []byte("P:foo\nV:1.0\nF:foo.apk\n\nP:bar\nF:bar.apk\n\n"),
	}))
	seeds = append(seeds, goldenTar(map[string][]byte{})) // пустой tar
	seeds = append(seeds, goldenTar(map[string][]byte{
		"README": []byte("not apkindex\n"),
	}))
	for _, s := range seeds {
		f.Add(s)
	}

	lim := parseLimits{
		decompressed: 1 << 16, entries: 64, fileSize: 1 << 14, lines: 1 << 14,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := collectIndex(parseAPKINDEXTar(bytes.NewReader(data), lim))
		second, secondErr := collectIndex(parseAPKINDEXTar(bytes.NewReader(data), lim))
		if !sameErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
		}
		for i := range first {
			if first[i].FilePath != second[i].FilePath || first[i].Name != second[i].Name {
				t.Fatalf("запись %d differs между прогонами:\n %+v\n vs\n %+v", i, first[i], second[i])
			}
		}
	})
}

// FuzzParseAPKINDEXGzip гоняет полный путь gzip → tar → текст на
// произвольных байтах как gzip-потоке. Инварианты те же: без паники,
// детерминизм. Отдельная точка входа — gzip-декодер тоже не должен
// падать на мусоре (ErrBadGzip, не паника).
func FuzzParseAPKINDEXGzip(f *testing.F) {
	indexText, err := os.ReadFile(filepath.Clean("testdata/APKINDEX.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	goldenDB := func(entries map[string][]byte) []byte {
		var tarBuf bytes.Buffer
		tw := tar.NewWriter(&tarBuf)
		for name, content := range entries {
			_ = tw.WriteHeader(&tar.Header{
				Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)),
			})
			_, _ = tw.Write(content)
		}
		_ = tw.Close()
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		_, _ = gw.Write(tarBuf.Bytes())
		_ = gw.Close()
		return gzBuf.Bytes()
	}
	seeds := [][]byte{
		[]byte(""),
		[]byte("not gzip"),
		{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}, // gzip magic + мусор
		goldenDB(map[string][]byte{
			"APKINDEX": indexText,
		}),
		goldenDB(map[string][]byte{}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	lim := parseLimits{
		decompressed: 1 << 16, entries: 64, fileSize: 1 << 14, lines: 1 << 14,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := collectIndex(parseAPKINDEX(bytes.NewReader(data), lim))
		second, secondErr := collectIndex(parseAPKINDEX(bytes.NewReader(data), lim))
		if !sameErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
		}
		for i := range first {
			if first[i].FilePath != second[i].FilePath {
				t.Fatalf("запись %d FilePath differs между прогонами", i)
			}
		}
		// ErrDecompressTooLarge валиден и не нарушает инвариант; прочие
		// ошибки тоже штатны — детерминизм проверен выше.
	})
}

// FuzzParseApkPkgInfo гоняет парсер .PKGINFO на произвольных байтах
// (байтовый текстовый формат — фаззинг обязателен, сессия 16).
// Инварианты: не паниковать, не зацикливаться, детерминизм. Потолок
// 64KiB: ввод > лимита → ErrPkgInfoTooLarge.
func FuzzParseApkPkgInfo(f *testing.F) {
	seeds := [][]byte{
		{0},
		[]byte(""),
		[]byte("garbage not pkginfo"),
		[]byte("# comment\npkgname = foo\npkgver = 1.0-r0\n"),
		[]byte("pkgname = foo\r\npkgver = 1.0-r0\r\n"),
		[]byte("no equals here\npkgname = bar\n"),
		[]byte("license = MIT\nlicense = BSD\n"),
		[]byte("size = not-a-number\nbuilddate = 5\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	// граничный корпус: ровно лимит и лимит+1.
	f.Add(bytes.Repeat([]byte("a"), maxPkgInfoSize))
	f.Add(bytes.Repeat([]byte("a"), maxPkgInfoSize+1))

	f.Fuzz(func(t *testing.T, data []byte) {
		first, ferr := ParsePkgInfo(bytes.NewReader(data))
		second, serr := ParsePkgInfo(bytes.NewReader(data))
		if !sameErr(ferr, serr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", ferr, serr)
		}
		if (first == nil) != (second == nil) {
			t.Fatalf("недетерминированный nil")
		}
		if first == nil {
			return
		}
		if first.Name != second.Name || first.Version != second.Version {
			t.Fatalf("недетерминированный разбор: %+v vs %+v", first, second)
		}
	})
}
