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

// index.plist — словарь proplib (XML-plist) pkgname → словарь полей.
// На x86_64 распакованный индекс ~20 MiB, поэтому тело в карту не
// собираем: ParseIndexPlist идёт по xml-токенам и отдаёт запись колбэку.
// Только encoding/xml — строковые сплиты/IndexOf по XML запрещены
// (урок rpm/pacman: `&lt;`/`&amp;`/`&apos;` в живых значениях, maintainer
// «Helmut Pozimski &lt;helmut@…&gt;»; факт 2026-09-17). Неизвестные
// ключи скипаются — proplib со временем добавляет поля.
//
// Инварианты защиты от adversarial-индекса (лимиты — константы ниже):
// значение поля ≤ 64 KiB, элементов массива ≤ 4096, записей ≤ 1 млн
// (OOM-гвард по прецеденту rpm-счётчика, сессия 34). Целочисленные поля
// — строгий strconv.ParseInt с ловлей переполнения (урок 88).

package xbps

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// maxFieldValue — потолок значения одного поля (string/integer).
	maxFieldValue = 64 << 10 // 64 KiB
	// maxArrayElems — потолок элементов одного массива полей.
	maxArrayElems = 4096
	// maxPackages — потолок числа записей-пакетов: гасит OOM-амплитуду
	// adversarial-индекса (прецедент rpm-счётчика, сессия 34).
	maxPackages = 1_000_000
)

// IndexEntry — одна запись index.plist. Поля — ключи proplib; массивы
// сохраняют порядок следования XML. PkgName — ключ внешнего словаря.
type IndexEntry struct {
	PkgName        string
	PkgVer         string
	Architecture   string
	ShortDesc      string
	Homepage       string
	License        string
	Maintainer     string
	FilenameSHA256 string
	FilenameSize   int64
	InstalledSize  int64
	RunDepends     []string
	Provides       []string
	ShlibRequires  []string
	ShlibProvides  []string
}

// fieldKind — ожидаемый тип значения известного ключа. kindUnknown —
// ключ не из нашего набора: значение скипается (forward-совместимость).
type fieldKind int

const (
	kindUnknown fieldKind = iota
	kindString
	kindInteger
	kindArray
)

// ParseIndexPlist стримингом читает index.plist и вызывает fn для
// каждой записи-пакета. Тело целиком в память не поднимается (r —
// поток index.plist из OpenRepoData). Ошибка формата/лимита —
// ErrBadPlist; ошибка fn возвращается как есть.
func ParseIndexPlist(r io.Reader, fn func(IndexEntry) error) error {
	if r == nil {
		return fmt.Errorf("%w: nil-источник", ErrBadPlist)
	}
	if fn == nil {
		return fmt.Errorf("%w: nil-колбэк", ErrBadPlist)
	}
	dec := xml.NewDecoder(r)
	if err := expectStart(dec, "plist"); err != nil {
		return err
	}
	if err := expectStart(dec, "dict"); err != nil {
		return err
	}
	return parseTopDict(dec, fn)
}

// parseTopDict разбирает внешний словарь pkgname → dict. Неизвестные
// токены между элементами (CharData/комментарии/procinst) игнорируются.
func parseTopDict(dec *xml.Decoder, fn func(IndexEntry) error) error {
	count := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return plistTokenErr(err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return nil // </dict> внешнего словаря
		case xml.StartElement:
			if t.Name.Local != "key" {
				return fmt.Errorf("%w: в словаре пакетов <%s>, ожидался <key>", ErrBadPlist, t.Name.Local)
			}
			pkg, err := readText(dec, t)
			if err != nil {
				return err
			}
			val, err := nextStart(dec)
			if err != nil {
				return err
			}
			if val.Name.Local != "dict" {
				return fmt.Errorf("%w: ключ %q: ожидался <dict>, получен <%s>", ErrBadPlist, pkg, val.Name.Local)
			}
			var entry IndexEntry
			entry.PkgName = pkg
			if err := parseEntryDict(dec, &entry); err != nil {
				return err
			}
			count++
			if count > maxPackages {
				return fmt.Errorf("%w: лимит записей пакетов %d", ErrBadPlist, maxPackages)
			}
			if err := fn(entry); err != nil {
				return err
			}
		}
	}
}

// parseEntryDict разбирает словарь полей одной записи.
func parseEntryDict(dec *xml.Decoder, entry *IndexEntry) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return plistTokenErr(err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return nil // </dict> записи
		case xml.StartElement:
			if t.Name.Local != "key" {
				return fmt.Errorf("%w: в словаре записи <%s>, ожидался <key>", ErrBadPlist, t.Name.Local)
			}
			key, err := readText(dec, t)
			if err != nil {
				return err
			}
			if err := parseField(dec, key, entry); err != nil {
				return err
			}
		}
	}
}

// parseField читает значение поля и раскладывает его в entry. Значения
// неизвестных ключей и неизвестных типов скипаются целиком.
func parseField(dec *xml.Decoder, key string, entry *IndexEntry) error {
	val, err := nextStart(dec)
	if err != nil {
		return err
	}
	kind := kindOf(key)
	switch val.Name.Local {
	case "string":
		s, err := readText(dec, val)
		if err != nil {
			return err
		}
		return assignString(entry, key, kind, s)
	case "integer":
		s, err := readText(dec, val)
		if err != nil {
			return err
		}
		return assignInteger(entry, key, kind, s)
	case "array":
		arr, err := readArray(dec, val)
		if err != nil {
			return err
		}
		return assignArray(entry, key, kind, arr)
	default:
		// data/date/real/dict и будущие типы proplib — скип целиком,
		// разбор не падает на незнакомом поле.
		return skipElement(dec)
	}
}

// assignString раскладывает строковое значение. Неизвестный ключ
// игнорируется; известный ключ иного типа — нарушение структуры.
func assignString(entry *IndexEntry, key string, kind fieldKind, val string) error {
	switch kind {
	case kindUnknown:
		return nil
	case kindString:
		setStringField(entry, key, val)
		return nil
	default:
		return typeMismatch(key, "string")
	}
}

// assignInteger раскладывает целочисленное значение: строгий ParseInt
// (переполнение/мусор → ErrBadPlist), затем запись поля.
func assignInteger(entry *IndexEntry, key string, kind fieldKind, val string) error {
	switch kind {
	case kindUnknown:
		return nil
	case kindInteger:
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			return fmt.Errorf("%w: ключ %q: %w", ErrBadPlist, key, err)
		}
		setIntField(entry, key, n)
		return nil
	default:
		return typeMismatch(key, "integer")
	}
}

// assignArray раскладывает массив строк. Пустой массив легален.
func assignArray(entry *IndexEntry, key string, kind fieldKind, val []string) error {
	switch kind {
	case kindUnknown:
		return nil
	case kindArray:
		setArrayField(entry, key, val)
		return nil
	default:
		return typeMismatch(key, "array")
	}
}

// kindOf возвращает ожидаемый тип известного ключа index.plist.
func kindOf(key string) fieldKind {
	switch key {
	case "pkgver", "architecture", "short_desc", "homepage", "license",
		"maintainer", "filename-sha256":
		return kindString
	case "filename-size", "installed_size":
		return kindInteger
	case "run_depends", "provides", "shlib-requires", "shlib-provides":
		return kindArray
	default:
		return kindUnknown
	}
}

// setStringField кладёт строку в поле записи; вызывается только для
// kindString-ключей.
func setStringField(entry *IndexEntry, key, val string) {
	switch key {
	case "pkgver":
		entry.PkgVer = val
	case "architecture":
		entry.Architecture = val
	case "short_desc":
		entry.ShortDesc = val
	case "homepage":
		entry.Homepage = val
	case "license":
		entry.License = val
	case "maintainer":
		entry.Maintainer = val
	case "filename-sha256":
		entry.FilenameSHA256 = val
	}
}

// setIntField кладёт целое в поле записи.
func setIntField(entry *IndexEntry, key string, val int64) {
	switch key {
	case "filename-size":
		entry.FilenameSize = val
	case "installed_size":
		entry.InstalledSize = val
	}
}

// setArrayField кладёт массив в поле записи.
func setArrayField(entry *IndexEntry, key string, val []string) {
	switch key {
	case "run_depends":
		entry.RunDepends = val
	case "provides":
		entry.Provides = val
	case "shlib-requires":
		entry.ShlibRequires = val
	case "shlib-provides":
		entry.ShlibProvides = val
	}
}

// typeMismatch — известный ключ пришёл с чужим типом значения.
func typeMismatch(key, got string) error {
	return fmt.Errorf("%w: ключ %q: неожиданный тип значения <%s>", ErrBadPlist, key, got)
}

// readText собирает символьные данные элемента до его закрытия.
// Вложенный элемент — нарушение структуры (string с ребёнком). Лимит
// maxFieldValue проверяется по мере накопления.
func readText(dec *xml.Decoder, start xml.StartElement) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", plistTokenErr(err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if b.Len()+len(t) > maxFieldValue {
				return "", fmt.Errorf("%w: значение поля превышает %d байт", ErrBadPlist, maxFieldValue)
			}
			b.Write(t)
		case xml.EndElement:
			return b.String(), nil
		case xml.StartElement:
			return "", fmt.Errorf("%w: вложенный <%s> в <%s>", ErrBadPlist, t.Name.Local, start.Name.Local)
		}
	}
}

// readArray читает <array> из <string>-элементов. Любой не-string
// элемент — нарушение структуры; превышение maxArrayElems — ErrBadPlist.
func readArray(dec *xml.Decoder, start xml.StartElement) ([]string, error) {
	out := []string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, plistTokenErr(err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return out, nil
		case xml.StartElement:
			if t.Name.Local != "string" {
				return nil, fmt.Errorf("%w: в массиве <%s> ожидался <string>, получен <%s>", ErrBadPlist, start.Name.Local, t.Name.Local)
			}
			s, err := readText(dec, t)
			if err != nil {
				return nil, err
			}
			if len(out) >= maxArrayElems {
				return nil, fmt.Errorf("%w: лимит элементов массива %d", ErrBadPlist, maxArrayElems)
			}
			out = append(out, s)
		}
	}
}

// skipElement пропускает элемент целиком, включая вложенные (для чужих
// типов значений вроде <dict>/<data>). Итеративно — без рекурсии на
// глубоко вложенном adversarial-вводе.
func skipElement(dec *xml.Decoder) error {
	for depth := 1; depth > 0; {
		tok, err := dec.Token()
		if err != nil {
			return plistTokenErr(err)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

// nextStart возвращает следующий StartElement, пропуская прочие токены.
// Закрывающий элемент там, где ожидалось значение, — нарушение структуры.
func nextStart(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, plistTokenErr(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			return xml.StartElement{}, fmt.Errorf("%w: преждевременное </%s>", ErrBadPlist, t.Name.Local)
		}
	}
}

// expectStart требует конкретный StartElement.
func expectStart(dec *xml.Decoder, name string) error {
	s, err := nextStart(dec)
	if err != nil {
		return err
	}
	if s.Name.Local != name {
		return fmt.Errorf("%w: ожидался <%s>, получен <%s>", ErrBadPlist, name, s.Name.Local)
	}
	return nil
}

// plistTokenErr переводит ошибку xml.Decoder в ErrBadPlist: обрыв XML
// (io.EOF/незакрытые элементы) и синтаксические ошибки — не паника.
func plistTokenErr(err error) error {
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: неожиданный конец XML", ErrBadPlist)
	}
	var syntax *xml.SyntaxError
	if errors.As(err, &syntax) {
		return fmt.Errorf("%w: %s (строка %d)", ErrBadPlist, syntax.Msg, syntax.Line)
	}
	return fmt.Errorf("%w: %w", ErrBadPlist, err)
}
