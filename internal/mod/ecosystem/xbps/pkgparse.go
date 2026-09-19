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

// .xbps-пакет Void Linux — ar-архив, возможно сжатый целиком: zstd
// (сигнатура 28 B5 2F FD), gzip (1F 8B) или raw ar (магия !<arch>\n).
// xz НЕ поддержан (ErrUnsupportedCompression) — встретится в живом
// upstream, разбор xz — отдельная микросессия по образцу 103.
//
// Члены ar классические (короткие имена, libarchive-формат xbps-create):
// ./props.plist, ./files.plist, payload-файлы. GNU-длинные имена (// и
// /N) в .xbps не бывают — ErrBadAr. Читаем ровно props.plist (индекс
// личного репо 141 строится из его полей); files.plist и payload —
// skip стримингом, payload в память не поднимается.
//
// Инварианты защиты от adversarial-ввода: декомпресс ≤ 1 GiB (zip-bomb
// guard, limitedReader parse.go); props.plist ≤ 1 MiB (ErrBadPlist из
// 132). Разбор XML-plist опирается на общие хелперы index.go
// (readText/readArray/skipElement/nextStart/…), продублированные
// механики нет.

package xbps

import (
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

	// arMagic / arHeaderSize — классический (System V/BSD) ar.
	arMagic      = "!<arch>\n"
	arHeaderSize = 60

	// propsName — имя члена с метаданными пакета.
	propsName = "props.plist"
)

// xzPrefix — первые 4 байта xz-потока (FD 37 7A 58). xz не разбираем:
// sentinel на весь класс «сжато, но не zstd/gzip».
const xzPrefix = "\xfd7zX"

// Ошибки контейнера .xbps — типизированные, сравнение через errors.Is.
var (
	ErrBadAr                  = errors.New("xbps: некорректный ar-архив пакета")
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

// OpenPackage детектит компрессию .xbps, обходит ar и отдаёт поля
// props.plist. Мусор — типизированные ошибки (errors.Is), паник нет.
// Тело пакета не буферизуется: payload скипается стримингом.
func OpenPackage(r io.Reader) (Props, error) {
	if r == nil {
		return Props{}, fmt.Errorf("%w: nil-источник", ErrBadAr)
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
			return Props{}, fmt.Errorf("%w: zstd: %w", ErrBadAr, err)
		}
		dec, closeFn = zr.IOReadCloser(), zr.Close
	case n >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		gz, err := gzip.NewReader(src)
		if err != nil {
			return Props{}, fmt.Errorf("%w: gzip: %w", ErrBadAr, err)
		}
		dec, closeFn = gz, func() { _ = gz.Close() }
	case n == len(xzPrefix) && string(head) == xzPrefix:
		return Props{}, fmt.Errorf("%w: xz", ErrUnsupportedCompression)
	default:
		dec, closeFn = src, func() {}
	}
	defer closeFn()

	limited := &limitedReader{r: dec, limit: maxDecompressed, sentinel: ErrDecompressTooLarge}
	return parsePkgAr(limited)
}

// parsePkgAr обходит члены ar, отдавая props.plist парсеру plist, а
// остальные тела скипая. Отсутствие props.plist — ErrPropsMissing.
func parsePkgAr(r io.Reader) (Props, error) {
	var magic [len(arMagic)]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return Props{}, arReadErr(err)
	}
	if string(magic[:]) != arMagic {
		return Props{}, fmt.Errorf("%w: сигнатура %q", ErrBadAr, magic[:])
	}
	for {
		hdr, ok, err := readArMemberHeader(r)
		if err != nil {
			return Props{}, err
		}
		if !ok {
			return Props{}, ErrPropsMissing
		}
		if hdr.name == propsName {
			if hdr.size > maxPropsSize {
				return Props{}, fmt.Errorf("%w: props.plist %d байт превышает %d", ErrBadPlist, hdr.size, maxPropsSize)
			}
			return parsePropsDict(io.LimitReader(r, hdr.size), maxPropsSize)
		}
		// CopyN, а не Copy(LimitReader): усечённый член обязан дать
		// ErrUnexpectedEOF → ErrBadAr, а не тихий успех.
		if _, err := io.CopyN(io.Discard, r, hdr.size); err != nil {
			return Props{}, arReadErr(err)
		}
		if hdr.size%2 != 0 {
			if _, err := io.CopyN(io.Discard, r, 1); err != nil {
				return Props{}, arReadErr(err)
			}
		}
	}
}

// arMember — разобранный заголовок члена ar.
type arMember struct {
	name string
	size int64
}

// readArMemberHeader читает 60-байтный заголовок члена. ok=false —
// чистый конец архива (больше членов нет), это не ошибка.
func readArMemberHeader(r io.Reader) (arMember, bool, error) {
	var raw [arHeaderSize]byte
	n, err := io.ReadFull(r, raw[:])
	if errors.Is(err, io.EOF) && n == 0 {
		return arMember{}, false, nil
	}
	if err != nil {
		return arMember{}, false, arReadErr(err)
	}
	if raw[58] != '`' || raw[59] != '\n' {
		return arMember{}, false, fmt.Errorf("%w: маркер конца заголовка члена", ErrBadAr)
	}
	name := normalizeArMemberName(string(raw[0:16]))
	if name == "" {
		return arMember{}, false, fmt.Errorf("%w: пустое имя члена", ErrBadAr)
	}
	if isGNULongName(name) {
		return arMember{}, false, fmt.Errorf("%w: GNU-длинное имя %q", ErrBadAr, name)
	}
	sizeStr := strings.TrimSpace(string(raw[48:58]))
	size, perr := strconv.ParseInt(sizeStr, 10, 64)
	if perr != nil || size < 0 {
		return arMember{}, false, fmt.Errorf("%w: размер члена %q", ErrBadAr, sizeStr)
	}
	return arMember{name: name, size: size}, true, nil
}

// normalizeArMemberName приводит имя члена к канону: хвостовые пробелы
// поля из 16 байт и ведущее «./» (libarchive) снимаются. Так
// «./props.plist» и «props.plist» — одно имя.
func normalizeArMemberName(raw string) string {
	name := strings.TrimRight(raw, " ")
	return strings.TrimPrefix(name, "./")
}

// isGNULongName распознаёт GNU-таблицу длинных имён «//» и ссылки «/N».
// В .xbps имена короткие, такие члены — признак чужого формата.
func isGNULongName(name string) bool {
	if name == "//" {
		return true
	}
	if len(name) < 2 || name[0] != '/' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// arReadErr оборачивает низкоуровневую ошибку чтения в ErrBadAr,
// сохраняя доменный ErrDecompressTooLarge как есть (единый на ветку,
// образец tarReadErr parse.go).
func arReadErr(err error) error {
	if errors.Is(err, ErrDecompressTooLarge) {
		return ErrDecompressTooLarge
	}
	return fmt.Errorf("%w: %w", ErrBadAr, err)
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
