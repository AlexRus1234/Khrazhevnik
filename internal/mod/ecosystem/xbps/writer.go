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

// Генерация index.plist (сессия 140) — обратная операция к стриминг-парсеру
// (index.go, сессия 132). Формат — XML-plist proplib: xml.Header + DOCTYPE
// + <plist version="1.0"><dict> с записью pkgname → словарь полей.
//
// Пишем только encoding/xml-токенами: энтити (`&`/`<`/`>`/апострофы) —
// зона stdlib, руками не экранируем (урок `'`/`-`, факт 2026-09-17: живые
// имена пакетов и maintainer содержат `&`, `<`, `>`). Побайтовое совпадение
// с xbps-rindex НЕ цель: клиенту важна валидность формата, а наш собственный
// парсер (132) обязан прочитать написанное без потерь (roundtrip).
//
// Детерминизм reindex: записи сортируются по PkgName, ключи внутри записи
// идут по алфавиту; две генерации одного набора дают байт-в-байт один
// результат. Тело (десятки-сотни KiB XML на живой репо) отдаётся потоком —
// полная строка индекса в памяти не собирается.

package xbps

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// plistDoctype — DOCTYPE живого plist (копия xbps-rindex: Apple DTD 1.0).
// Собственный парсер пропускает его как Directive (nextStart), но клиенты
// proplib ожидают каноническую шапку.
const plistDoctype = `<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n"

// IndexOut — запись index.plist на запись: ключ словаря (PkgName) плюс
// поля props.plist пакета (Props, сессия 137) и вычисленные генератором
// (141) filename-sha256/filename-size — они зависят от arch-группы, поэтому
// передаются готовыми, а не считаются здесь.
type IndexOut struct {
	Props
	FilenameSHA256 string
	FilenameSize   int64
}

// WriteIndexPlist потоково пишет index.plist из entries. Порядок записей —
// по PkgName (копия входа, детерминизм независимо от порядка вызова), поля
// записи — по алфавиту, пустые поля опускаются (как в живом индексе).
// Написание валидно для ParseIndexPlist (roundtrip). nil-приёмник —
// ErrBadPlist (контракт nil-источника парсера).
func WriteIndexPlist(w io.Writer, entries []IndexOut) error {
	if w == nil {
		return fmt.Errorf("%w: nil-приёмник", ErrBadPlist)
	}
	sorted := make([]IndexOut, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PkgName < sorted[j].PkgName })

	if _, err := io.WriteString(w, xml.Header+plistDoctype); err != nil {
		return fmt.Errorf("xbps: index.plist: пролог: %w", err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("\t", "")
	if err := enc.EncodeToken(xml.StartElement{
		Name: xml.Name{Local: "plist"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "version"}, Value: "1.0"}},
	}); err != nil {
		return fmt.Errorf("xbps: index.plist: <plist>: %w", err)
	}
	if err := startElem(enc, "dict"); err != nil {
		return fmt.Errorf("xbps: index.plist: <dict>: %w", err)
	}
	for _, e := range sorted {
		if err := writeIndexEntry(enc, e); err != nil {
			return fmt.Errorf("xbps: index.plist: пакет %q: %w", e.PkgName, err)
		}
	}
	if err := endElem(enc, "dict"); err != nil {
		return fmt.Errorf("xbps: index.plist: </dict>: %w", err)
	}
	if err := endElem(enc, "plist"); err != nil {
		return fmt.Errorf("xbps: index.plist: </plist>: %w", err)
	}
	if err := enc.Flush(); err != nil {
		return fmt.Errorf("xbps: index.plist: сброс буфера: %w", err)
	}
	return nil
}

// writeIndexEntry пишет пару <key>PkgName</key><dict>…</dict>. Поля — в
// алфавитном порядке ключей (детерминизм байт-в-байт), только непустые.
func writeIndexEntry(enc *xml.Encoder, e IndexOut) error {
	if err := writeKey(enc, e.PkgName); err != nil {
		return err
	}
	if err := startElem(enc, "dict"); err != nil {
		return err
	}
	// Поля по алфавиту ключей: порядок фиксирован списком, не map
	// (детерминизм байт-в-байт). Пустые поля write*Field пропускают сами.
	fields := []func() error{
		func() error { return writeStringField(enc, "architecture", e.Architecture) },
		func() error { return writeStringField(enc, "filename-sha256", e.FilenameSHA256) },
		func() error { return writeIntField(enc, "filename-size", e.FilenameSize) },
		func() error { return writeStringField(enc, "homepage", e.Homepage) },
		func() error { return writeIntField(enc, "installed_size", e.InstalledSize) },
		func() error { return writeStringField(enc, "license", e.License) },
		func() error { return writeStringField(enc, "maintainer", e.Maintainer) },
		func() error { return writeStringField(enc, "pkgver", e.PkgVer) },
		func() error { return writeArrayField(enc, "provides", e.Provides) },
		func() error { return writeArrayField(enc, "run_depends", e.RunDepends) },
		func() error { return writeStringField(enc, "short_desc", e.ShortDesc) },
		func() error { return writeStringField(enc, "source-revisions", e.SourceRevisions) },
		func() error { return writeStringField(enc, "version", e.Version) },
	}
	for _, write := range fields {
		if err := write(); err != nil {
			return err
		}
	}
	return endElem(enc, "dict")
}

// writeKey пишет <key>…</key>.
func writeKey(enc *xml.Encoder, key string) error {
	if err := startElem(enc, "key"); err != nil {
		return err
	}
	if err := enc.EncodeToken(xml.CharData(key)); err != nil {
		return err
	}
	return endElem(enc, "key")
}

// writeStringField пишет <key>key</key><string>val</string>; пустое
// значение — пропуск поля.
func writeStringField(enc *xml.Encoder, key, val string) error {
	if val == "" {
		return nil
	}
	if err := writeKey(enc, key); err != nil {
		return err
	}
	if err := startElem(enc, "string"); err != nil {
		return err
	}
	if err := enc.EncodeToken(xml.CharData(val)); err != nil {
		return err
	}
	return endElem(enc, "string")
}

// writeIntField пишет <integer>; нулевое значение — пропуск поля.
func writeIntField(enc *xml.Encoder, key string, val int64) error {
	if val == 0 {
		return nil
	}
	if err := writeKey(enc, key); err != nil {
		return err
	}
	if err := startElem(enc, "integer"); err != nil {
		return err
	}
	if err := enc.EncodeToken(xml.CharData(strconv.FormatInt(val, 10))); err != nil {
		return err
	}
	return endElem(enc, "integer")
}

// writeArrayField пишет <array> из <string>; пустой массив — пропуск поля.
func writeArrayField(enc *xml.Encoder, key string, val []string) error {
	if len(val) == 0 {
		return nil
	}
	if err := writeKey(enc, key); err != nil {
		return err
	}
	if err := startElem(enc, "array"); err != nil {
		return err
	}
	for _, s := range val {
		if err := startElem(enc, "string"); err != nil {
			return err
		}
		if err := enc.EncodeToken(xml.CharData(s)); err != nil {
			return err
		}
		if err := endElem(enc, "string"); err != nil {
			return err
		}
	}
	return endElem(enc, "array")
}

// startElem/endElem — тонкие обёртки EncodeToken для узлов без namespace.
func startElem(enc *xml.Encoder, name string) error {
	return enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}})
}

func endElem(enc *xml.Encoder, name string) error {
	return enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: name}})
}
