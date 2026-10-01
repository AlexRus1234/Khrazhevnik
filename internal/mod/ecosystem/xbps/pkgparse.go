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

// .xbps-пакет Void Linux — tar-архив, сжатый целиком: zstd (сигнатура
// 28 B5 2F FD), gzip (1F 8B) или raw tar. xz НЕ поддержан
// (ErrUnsupportedCompression) — встретится в живом upstream, разбор xz —
// отдельная микросессия по образцу 103.
//
// Члены tar канонические (префикс «./», libarchive-формат xbps-create):
// ./props.plist, ./files.plist, payload-файлы. Читаем ровно
// ./props.plist (индекс личного репо 141 строится из его полей);
// files.plist и payload скипаются стримингом (tar.Reader.Next сам
// дочитывает пропущенный член в io.Discard) — payload в память не
// поднимается. Имя без канонического префикса — не наш член: так
// отсекается чужой контейнер с членом «props.plist».
//
// Живой факт 2026-10-01: Mustache-4.1_1.x86_64.xbps с
// repo-default.voidlinux.org — zstd(tar) с записями ./props.plist,
// ./files.plist и payload. Формата «zstd(raw ar)» у Void не существует
// (by design xbps-create всегда пакует tar) — прежняя ar-ветка 137
// разбирала несуществующий в природе формат, и reindex любого реального
// пакета падал ErrPropsMissing.
//
// Инварианты защиты от adversarial-ввода: декомпресс ≤ 1 GiB (zip-bomb
// guard, limitedReader parse.go); props.plist ≤ 1 MiB (ErrBadPlist из
// 132). Разбор XML-plist опирается на общие хелперы index.go
// (readText/readArray/skipElement/nextStart/…), продублированные
// механики нет.

package xbps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	// maxPropsSize — потолок тела props.plist: в живом пакете ~782
	// байта, запас кратный; превышение — ErrBadPlist.
	maxPropsSize = int64(1 << 20) // 1 MiB

	// propsName — имя члена tar с метаданными пакета. Канонический
	// префикс «./» пишет сам xbps-create (libarchive); имя без префикса
	// принадлежит чужому контейнеру и нашим членом не считается.
	propsName = "./props.plist"
)

// xzPrefix — первые 4 байта xz-потока (FD 37 7A 58). xz не разбираем:
// sentinel на весь класс «сжато, но не zstd/gzip».
const xzPrefix = "\xfd7zX"

// Ошибки контейнера .xbps — типизированные, сравнение через errors.Is.
var (
	ErrBadPackage             = errors.New("xbps: некорректный контейнер пакета")
	ErrUnsupportedCompression = errors.New("xbps: неподдерживаемая компрессия пакета")
	ErrPropsMissing           = errors.New("xbps: в пакете отсутствует props.plist")
)

// Props — поля props.plist, нужные генератору личных репозиториев (141)
// для записи index.plist. Типы proplib: строки, целое, массивы строк.
type Props struct {
	PkgName         string
	PkgVer          string
	Version         string
	Architecture    string
	ShortDesc       string
	Homepage        string
	License         string
	Maintainer      string
	InstalledSize   int64
	SourceRevisions string
	RunDepends      []string
	Provides        []string
}

// OpenPackage детектит компрессию .xbps, обходит tar-записи и отдаёт
// поля props.plist. Мусор — типизированные ошибки (errors.Is), паник
// нет. Тело пакета не буферизуется: payload скипается стримингом.
func OpenPackage(r io.Reader) (Props, error) {
	if r == nil {
		return Props{}, fmt.Errorf("%w: nil-источник", ErrBadPackage)
	}
	head := make([]byte, len(zstdMagic))
	n, _ := io.ReadFull(r, head)
	// MultiReader: декодер не должен видеть «съеденных» байт magic
	// (урок 103).
	src := io.MultiReader(bytes.NewReader(head[:n]), r)

	var (
		dec     io.Reader
		closeFn func()
	)
	switch {
	case n == len(zstdMagic) && string(head) == zstdMagic:
		zr, err := zstd.NewReader(src)
		if err != nil {
			return Props{}, fmt.Errorf("%w: zstd: %w", ErrBadPackage, err)
		}
		dec, closeFn = zr.IOReadCloser(), zr.Close
	case n >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		gz, err := gzip.NewReader(src)
		if err != nil {
			return Props{}, fmt.Errorf("%w: gzip: %w", ErrBadPackage, err)
		}
		dec, closeFn = gz, func() { _ = gz.Close() }
	case n == len(xzPrefix) && string(head) == xzPrefix:
		return Props{}, fmt.Errorf("%w: xz", ErrUnsupportedCompression)
	default:
		dec, closeFn = src, func() {}
	}
	defer closeFn()

	limited := &limitedReader{r: dec, limit: maxDecompressed, sentinel: ErrDecompressTooLarge}
	return parsePkgTar(limited)
}

// parsePkgTar обходит tar-записи, отдавая тело ./props.plist парсеру
// plist, а остальные члены скипая. Отсутствие props.plist — ErrPropsMissing.
func parsePkgTar(r io.Reader) (Props, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return Props{}, ErrPropsMissing
			}
			// Next дочитывает пропущенный член: усечённое тело даёт
			// ErrUnexpectedEOF → ErrBadPackage, а не тихий успех.
			return Props{}, pkgReadErr(err)
		}
		// Только регулярный файл с каноническим именем члена: payload
		// и files.plist дочитываются tar.Reader'ом в io.Discard.
		if hdr.Typeflag != tar.TypeReg || hdr.Name != propsName {
			continue
		}
		if hdr.Size > maxPropsSize {
			return Props{}, fmt.Errorf("%w: props.plist %d байт превышает %d", ErrBadPlist, hdr.Size, maxPropsSize)
		}
		return parsePropsDict(io.LimitReader(tr, hdr.Size), maxPropsSize)
	}
}

// pkgReadErr оборачивает низкоуровневую ошибку чтения в ErrBadPackage,
// сохраняя доменный ErrDecompressTooLarge как есть (единый на ветку,
// образец tarReadErr parse.go).
func pkgReadErr(err error) error {
	if errors.Is(err, ErrDecompressTooLarge) {
		return ErrDecompressTooLarge
	}
	return fmt.Errorf("%w: %w", ErrBadPackage, err)
}

// parsePropsDict разбирает props.plist — плоский proplib-словарь
// метаданных (в отличие от index.plist, где словарь словарей). max —
// совокупный бюджет байт значений: adversarial-словарь гасится
// ErrBadPlist, а не OOM. Значения чужих типов (data/date/real/dict) и
// неизвестные ключи скипаются (forward-совместимость proplib).
func parsePropsDict(r io.Reader, max int64) (Props, error) {
	if r == nil {
		return Props{}, fmt.Errorf("%w: nil-источник", ErrBadPlist)
	}
	dec := xml.NewDecoder(r)
	if err := expectStart(dec, "plist"); err != nil {
		return Props{}, err
	}
	if err := expectStart(dec, "dict"); err != nil {
		return Props{}, err
	}
	var p Props
	budget := max
	for {
		tok, err := dec.Token()
		if err != nil {
			return Props{}, plistTokenErr(err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return p, nil // </dict> словаря props
		case xml.StartElement:
			if t.Name.Local != "key" {
				return Props{}, fmt.Errorf("%w: в словаре props <%s>, ожидался <key>", ErrBadPlist, t.Name.Local)
			}
			key, err := readText(dec, t)
			if err != nil {
				return Props{}, err
			}
			if err := assignProp(dec, key, &p, &budget); err != nil {
				return Props{}, err
			}
		}
	}
}

// assignProp читает значение поля props.plist и раскладывает его. Бюджет
// списывается по объёму значений (строки/числа/элементы массива).
func assignProp(dec *xml.Decoder, key string, p *Props, budget *int64) error {
	val, err := nextStart(dec)
	if err != nil {
		return err
	}
	switch val.Name.Local {
	case "string":
		s, err := readText(dec, val)
		if err != nil {
			return err
		}
		if err := spend(budget, int64(len(s))); err != nil {
			return err
		}
		setPropString(p, key, s)
		return nil
	case "integer":
		s, err := readText(dec, val)
		if err != nil {
			return err
		}
		if err := spend(budget, int64(len(s))); err != nil {
			return err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return fmt.Errorf("%w: ключ %q: %w", ErrBadPlist, key, err)
		}
		setPropInt(p, key, n)
		return nil
	case "array":
		arr, err := readArray(dec, val)
		if err != nil {
			return err
		}
		for _, s := range arr {
			if err := spend(budget, int64(len(s))); err != nil {
				return err
			}
		}
		setPropArray(p, key, arr)
		return nil
	default:
		return skipElement(dec)
	}
}

// spend уменьшает бюджет словаря; исчерпание — ErrBadPlist.
func spend(budget *int64, n int64) error {
	*budget -= n
	if *budget < 0 {
		return fmt.Errorf("%w: бюджет словаря props исчерпан", ErrBadPlist)
	}
	return nil
}

// setPropString раскладывает строковое поле; неизвестные ключи
// игнорируются (proplib добавляет поля со временем).
func setPropString(p *Props, key, val string) {
	switch key {
	case "pkgname":
		p.PkgName = val
	case "pkgver":
		p.PkgVer = val
	case "version":
		p.Version = val
	case "architecture":
		p.Architecture = val
	case "short_desc":
		p.ShortDesc = val
	case "homepage":
		p.Homepage = val
	case "license":
		p.License = val
	case "maintainer":
		p.Maintainer = val
	case "source-revisions":
		p.SourceRevisions = val
	}
}

// setPropInt раскладывает целочисленное поле.
func setPropInt(p *Props, key string, val int64) {
	if key == "installed_size" {
		p.InstalledSize = val
	}
}

// setPropArray раскладывает массив строк; пустой массив легален.
func setPropArray(p *Props, key string, val []string) {
	switch key {
	case "run_depends":
		p.RunDepends = val
	case "provides":
		p.Provides = val
	}
}
