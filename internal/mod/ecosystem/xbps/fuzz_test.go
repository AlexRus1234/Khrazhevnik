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

package xbps

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// maxTruncationSeeds — сколько обрезанных префиксов валидного контейнера
// кладём в seed-корпус. Контейнер крошечный (~сотни байт), поэтому при
// обычном размере кладём КАЖДОЕ смещение; шаг — только страховка от
// разросшегося сида (корпус не должен пухнуть).
const maxTruncationSeeds = 512

// FuzzParseRepoData гоняет ВСЮ композицию repodata на произвольных
// байтах: zstd → tar → index.plist (OpenRepoData → ParseIndexPlist).
// Фаззинг одного таргета на композицию ломает реальный вход, а не слои
// поодиночке (решение сессии 134). Инварианты: не паниковать, не
// зацикливаться (таймаут ловит), повторный прогон тех же байт даёт тот
// же результат и то же число записей. Колбэк — только счётчик
// (io.Discard-семантика): тела ~20 MiB не накапливаются, иначе фаззер
// съедает память раньше, чем найдёт баг.
func FuzzParseRepoData(f *testing.F) {
	// Валидный мини-контейнер (index → meta → stage) для обрезки.
	validIndex := []byte(`<?xml version="1.0"?><plist><dict><key>0ad</key>` +
		`<dict><key>pkgver</key><string>0ad-0.27.1_6</string></dict></dict></plist>`)
	validMeta := []byte(`<?xml version="1.0"?><plist><dict><key>public-key</key>` +
		`<data>QUFBQQ==</data></dict></plist>`)
	valid := newRepoZstd(f,
		tarFile{indexName, validIndex},
		tarFile{metaName, validMeta},
		tarFile{stageName, nil},
	)
	golden, err := os.ReadFile(filepath.Clean(goldenRepodata))
	if err != nil {
		f.Fatalf("чтение %s: %v", goldenRepodata, err)
	}
	// index.plist не первой записью — ErrIndexNotFirst.
	metaFirst := newRepoZstd(f,
		tarFile{metaName, validMeta},
		tarFile{indexName, validIndex},
	)
	// index.plist без index-meta.plist — ошибка на closeFn.
	indexOnly := newRepoZstd(f, tarFile{indexName, validIndex})
	// Валидный XML, но не plist-корень («без первой записи») —
	// ErrBadPlist, не паника.
	noPlistRoot := newRepoZstd(f,
		tarFile{indexName, []byte(`<dict><key>0ad</key><dict/></dict>`)},
		tarFile{metaName, validMeta},
	)

	seeds := [][]byte{
		nil,
		[]byte("not a repodata at all"),
		append([]byte(zstdMagic), []byte("garbage after magic")...),
		golden,
		valid,
		metaFirst,
		indexOnly,
		noPlistRoot,
	}
	step := 1
	if len(valid) > maxTruncationSeeds {
		step = len(valid)/maxTruncationSeeds + 1
	}
	for i := 0; i < len(valid); i += step {
		seeds = append(seeds, valid[:i])
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		firstCount, firstErr := runRepoData(data)
		// Повторный разбор тех же байт обязан дать идентичный результат —
		// детерминизм (скрытое состояние у парсера недопустимо).
		secondCount, secondErr := runRepoData(data)
		if !sameRepoErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if firstCount != secondCount {
			t.Fatalf("число записей скачет: %d vs %d", firstCount, secondCount)
		}
	})
}

// runRepoData прогоняет композицию, всегда освобождая ресурсы декодера
// (closeFn владеет zstd-горутинами, урок 77). Возвращает число записей
// и первую ошибку (open/parse/close).
func runRepoData(data []byte) (int, error) {
	index, closeFn, err := OpenRepoData(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	count := 0
	perr := ParseIndexPlist(index, func(IndexEntry) error {
		count++
		return nil
	})
	_, cerr := closeFn()
	if perr != nil {
		return count, perr
	}
	return count, cerr
}

// sameRepoErr сравнивает ошибки двух прогонов: nil-nil, sentinel через
// errors.Is (типизированные обёртки), иначе — равенство текста (сырые
// ошибки xml/zstd каждый прогон создаются заново). Текст детерминирован,
// если у парсера нет скрытого состояния.
func sameRepoErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if errors.Is(a, b) || errors.Is(b, a) {
		return true
	}
	return a.Error() == b.Error()
}
