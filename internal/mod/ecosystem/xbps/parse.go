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

// Контейнер <arch>-repodata Void Linux: zstd (сигнатура 28 B5 2F FD) →
// pax-tar из трёх записей — index.plist (XML-plist, словарь pkgname →
// поля, ~20 MiB распакованным на x86_64), index-meta.plist (~1.4 KiB,
// публичный ключ) и stage.plist (у Void пустой, но запись присутствует).
// Порядок записей фиксирован клиентом libxbps (lib/repo.c:
// repo_read_index требует index.plist первой записью, repo_read_meta —
// следующей index-meta.plist): наш парсер так же строг.
//
// Инварианты защиты от adversarial-ввода:
//   - декомпресс ≤ 1 GiB (zip-bomb guard, образец pacman parse.go:24-28);
//   - plist-запись index-meta.plist ≤ 64 KiB.
//
// index.plist отдаётся потребителю потоком (его парсит index.go, сессия
// 132), НЕ буферизуется: распакованные ~20 MiB не держим в памяти. Tar
// последователен, поэтому index-meta.plist физически идёт ПОСЛЕ
// index.plist — meta возвращает закрывающая функция closeFn, которую
// потребитель вызывает, вычитав index-поток. Буферизовать index ради
// немедленного meta нельзя: это нарушило бы потоковость и дало бы OOM
// на zstd-бомбе.

package xbps

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

const (
	// maxDecompressed — потолок разжатого потока (zip-bomb guard);
	// общий инвариант парсеров чужих форматов (pacman parse.go:24-28).
	maxDecompressed = int64(1 << 30) // 1 GiB
	// maxMetaSize — потолок записи index-meta.plist: у Void ~1.4 KiB,
	// запас кратный; превышение — ErrBadTar.
	maxMetaSize = 64 << 10 // 64 KiB

	// Имена записей repodata — константы libxbps (xbps.h).
	indexName = "index.plist"
	metaName  = "index-meta.plist"
	stageName = "stage.plist"

	// zstdMagic — сигнатура zstd-кадра. Компрессия repodata только
	// zstd (Void публикует zstd, наши генераторы тоже); gzip/xz/none —
	// отдельная микросессия по образцу 103.
	zstdMagic = "\x28\xb5\x2f\xfd"
)

// Ошибки контейнера — типизированные, сравнение через errors.Is.
var (
	ErrBadZstd            = errors.New("xbps: некорректный zstd-поток")
	ErrBadTar             = errors.New("xbps: некорректный tar-поток repodata")
	ErrIndexMissing       = errors.New("xbps: в repodata отсутствует index.plist")
	ErrIndexNotFirst      = errors.New("xbps: index.plist не первая запись repodata")
	ErrDecompressTooLarge = errors.New("xbps: декомпрессия превысила лимит")
)

// OpenRepoData разворачивает контейнер repodata: zstd по magic → tar.
// Возвращает index — поток тела index.plist (io.Reader, парсит 132) и
// closeFn — закрывающую функцию: она дочитывает index (если потребитель
// не дочитал), читает index-meta.plist (≤ 64 KiB), пропускает остальные
// записи стримингом и гасит zstd-декодер. closeFn обязателен к вызову:
// он владеет ресурсами декодера (горутины zstd, урок 77) и возвращает
// meta-байты. Повторный вызов closeFn не предусмотрен. Ошибки
// типизированы (errors.Is).
func OpenRepoData(r io.Reader) (index io.Reader, closeFn func() ([]byte, error), err error) {
	if r == nil {
		return nil, nil, fmt.Errorf("%w: nil-источник", ErrBadZstd)
	}
	head := make([]byte, len(zstdMagic))
	n, _ := io.ReadFull(r, head)
	if n != len(zstdMagic) || string(head[:n]) != zstdMagic {
		return nil, nil, fmt.Errorf("%w: сигнатура % x", ErrBadZstd, head[:n])
	}
	// MultiReader: потребитель не должен видеть «съеденных» байт magic
	// (урок 103).
	rest := io.MultiReader(bytes.NewReader(head[:n]), r)
	zr, err := zstd.NewReader(rest)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBadZstd, err)
	}
	limited := &limitedReader{r: zr.IOReadCloser(), limit: maxDecompressed, sentinel: ErrDecompressTooLarge}
	tr := tar.NewReader(limited)

	hdr, err := tr.Next()
	if err != nil {
		zr.Close()
		return nil, nil, firstEntryErr(err)
	}
	if hdr.Name != indexName {
		zr.Close()
		return nil, nil, fmt.Errorf("%w: первая запись %q", ErrIndexNotFirst, hdr.Name)
	}

	closeFn = func() ([]byte, error) {
		defer zr.Close()
		return readRepoMeta(tr)
	}
	return tr, closeFn, nil
}

// readRepoMeta дочитывает index.plist (если потребитель не дочитал),
// читает следующую запись index-meta.plist (≤ 64 KiB), пропускает
// остальные записи стримингом (archive_read_data_skip-семантика) и
// возвращает meta-байты.
func readRepoMeta(tr *tar.Reader) ([]byte, error) {
	if _, err := io.Copy(io.Discard, tr); err != nil {
		return nil, tarReadErr(err)
	}
	mhdr, err := tr.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: отсутствует %s", ErrBadTar, metaName)
		}
		return nil, tarReadErr(err)
	}
	if mhdr.Name != metaName {
		return nil, fmt.Errorf("%w: ожидалась %s, получена %q", ErrBadTar, metaName, mhdr.Name)
	}
	if mhdr.Size > maxMetaSize {
		return nil, fmt.Errorf("%w: %s %d байт превышает %d", ErrBadTar, metaName, mhdr.Size, maxMetaSize)
	}
	meta := make([]byte, mhdr.Size)
	if mhdr.Size > 0 {
		if _, err := io.ReadFull(tr, meta); err != nil {
			return nil, tarReadErr(err)
		}
	}
	for {
		if _, err := tr.Next(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, tarReadErr(err)
		}
	}
	return meta, nil
}

// firstEntryErr классифицирует ошибку чтения первой записи tar: пустой
// архив — отсутствие индекса, превышение декомпресс-капа — доменная
// ошибка без обёртки, прочее — битый tar.
func firstEntryErr(err error) error {
	switch {
	case errors.Is(err, io.EOF):
		return ErrIndexMissing
	case errors.Is(err, ErrDecompressTooLarge):
		return ErrDecompressTooLarge
	default:
		return tarReadErr(err)
	}
}

// tarReadErr оборачивает низкоуровневую ошибку чтения в ErrBadTar,
// сохраняя доменный ErrDecompressTooLarge как есть (единый на ветку).
func tarReadErr(err error) error {
	if errors.Is(err, ErrDecompressTooLarge) {
		return ErrDecompressTooLarge
	}
	return fmt.Errorf("%w: %w", ErrBadTar, err)
}

// limitedReader считает байты и возвращает sentinel при превышении
// лимита. Не io.LimitReader: последний отдаёт io.EOF при достижении
// лимита, что неотличимо от настоящего конца потока; здесь нужна именно
// ошибка с типом. Дубль pacman parse.go:306-323 — mod→mod импорты
// запрещены depguard'ом, адаптеры самодостаточны.
type limitedReader struct {
	r        io.Reader
	n        int64
	limit    int64
	sentinel error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n >= l.limit {
		return 0, l.sentinel
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.limit {
		return n, l.sentinel
	}
	return n, err
}
