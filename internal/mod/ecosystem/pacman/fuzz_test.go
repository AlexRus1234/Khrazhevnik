// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; even without the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package pacman

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// FuzzParsePacmanDB гоняет парсер tar/desc на произвольных байтах,
// поданных как распакованный tar-поток (точка входа ParseDBTar — без
// zstd, чтобы фаззер исследовал именно формат tar+desc, а не zstd-кодек).
// Инварианты: не паниковать, не зацикливаться (таймаут теста ловит),
// повторный разбор тех же байт даёт тот же набор записей (детерминизм).
// Потолки стянуты до маленьких значений, чтобы фаззер успевал покрыть
// много разных форм за 20с, а не вяз в одном гигантском вводе.
func FuzzParsePacmanDB(f *testing.F) {
	// Посев-корпус: золотые фикстуры (собранные в tar) + синтетические
	// формы (пустой, битый tar, desc без полей, многострочное поле).
	seeds := [][]byte{
		[]byte(""),
		[]byte("garbage not a tar"),
		[]byte("%FILENAME%\nfoo.pkg.tar.zst\n"),
	}
	// золотые desc, упакованные в tar
	desc1, err := os.ReadFile(filepath.Clean("testdata/desc-1.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	desc2, err := os.ReadFile(filepath.Clean("testdata/desc-2.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	// собираем tar в памяти (без t.Helper — это не тест)
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
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	}))
	seeds = append(seeds, goldenTar(map[string][]byte{
		"foo/desc": []byte("%NAME%\nfoo\n%DEPENDS%\na\nb\nc\n%VERSION%\n1.0\n"),
	}))
	seeds = append(seeds, goldenTar(map[string][]byte{})) // пустой tar
	for _, s := range seeds {
		f.Add(s)
	}

	// fuzzLimits — стянутые потолки: маленький лимит записей и размера
	// desc, чтобы за 20с покрыть больше входов, а не вязнуть в одном.
	lim := parseLimits{
		decompressed: 1 << 16, entries: 64, descSize: 1 << 12, descLines: 256,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := collectDB(parseDBTar(bytes.NewReader(data), lim))
		// Повторный разбор тех же байт обязан дать идентичный результат —
		// детерминизм парсера. Разница означает скрытое состояние (нельзя).
		second, secondErr := collectDB(parseDBTar(bytes.NewReader(data), lim))
		if !sameErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
		}
		for i := range first {
			if first[i].Filename != second[i].Filename || first[i].Name != second[i].Name {
				t.Fatalf("запись %d differs между прогонами:\n %+v\n vs\n %+v", i, first[i], second[i])
			}
		}
	})
}

// FuzzParsePacmanDBZstd гоняет полный путь zstd → tar → desc на
// произвольных байтах как zstd-потоке. Инварианты те же: без паники,
// детерминизм. Отдельная точка входа — zstd-декодер тоже не должен
// падать на мусоре (инвариант сессии 12: ErrBadZstd, не паника).
func FuzzParsePacmanDBZstd(f *testing.F) {
	// Посев: zstd-сжатые золотые фикстуры + синтетика (пустой, мусор).
	desc1, err := os.ReadFile(filepath.Clean("testdata/desc-1.golden"))
	if err != nil {
		f.Fatalf("чтение посева: %v", err)
	}
	// собираем tar → zst
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
		var zstBuf bytes.Buffer
		zw, _ := zstd.NewWriter(&zstBuf)
		_, _ = zw.Write(tarBuf.Bytes())
		_ = zw.Close()
		return zstBuf.Bytes()
	}
	seeds := [][]byte{
		[]byte(""),
		[]byte("not zstd"),
		{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x00, 0x00}, // zstd magic + мусор
		goldenDB(map[string][]byte{
			"pacman-example-1.0-1-x86_64/desc": desc1,
		}),
		goldenDB(map[string][]byte{}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	lim := parseLimits{
		decompressed: 1 << 16, entries: 64, descSize: 1 << 12, descLines: 256,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := collectDB(parseDB(bytes.NewReader(data), lim))
		second, secondErr := collectDB(parseDB(bytes.NewReader(data), lim))
		if !sameErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("число записей скачет: %d vs %d", len(first), len(second))
		}
		for i := range first {
			if first[i].Filename != second[i].Filename {
				t.Fatalf("запись %d Filename differs между прогонами", i)
			}
		}
		// ErrDecompressTooLarge валиден и не нарушает инвариант; прочие
		// ошибки тоже штатны — детерминизм проверен выше.
	})
}
