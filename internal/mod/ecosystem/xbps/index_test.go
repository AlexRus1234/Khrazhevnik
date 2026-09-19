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
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// realIndex — срез живого x86_64-индекса с РЕАЛЬНЫМИ именами (урок 65):
// 0ad с provides cmd:*, libstdc++ с pkgver «~», значения с `+`/`>=`,
// maintainer с `&lt;`+`&amp;` (энтити раскодирует stdlib).
const realIndex = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>0ad</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>filename-sha256</key>
		<string>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</string>
		<key>filename-size</key>
		<integer>9157632</integer>
		<key>homepage</key>
		<string>https://play0ad.com/</string>
		<key>installed_size</key>
		<integer>24227840</integer>
		<key>license</key>
		<string>GPL-2.0-or-later</string>
		<key>maintainer</key>
		<string>Helmut Pozimski &lt;helmut@example.org&gt; &amp; void</string>
		<key>pkgver</key>
		<string>0ad-0.27.1_6</string>
		<key>provides</key>
		<array>
			<string>cmd:0ad</string>
			<string>cmd:pyrogenesis</string>
		</array>
		<key>run_depends</key>
		<array>
			<string>glibc&gt;=2.41_1</string>
			<string>libstdc++&gt;=14.2.1_1</string>
		</array>
		<key>short_desc</key>
		<string>GPL licensed RTS, similar to Age of Empires</string>
	</dict>
	<key>libstdc++</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>pkgver</key>
		<string>libstdc++-14.2.1_1~rc1</string>
		<key>shlib-provides</key>
		<array>
			<string>libstdc++.so.6</string>
		</array>
		<key>shlib-requires</key>
		<array>
			<string>libc.so.6</string>
			<string>libgcc_s.so.1</string>
		</array>
	</dict>
</dict>
</plist>
`

// parseIndex собирает все записи разбора в срез.
func parseIndex(t *testing.T, xml string) ([]IndexEntry, error) {
	t.Helper()
	var out []IndexEntry
	err := ParseIndexPlist(strings.NewReader(xml), func(e IndexEntry) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

func TestParseIndexPlistRealIndex(t *testing.T) {
	got, err := parseIndex(t, realIndex)
	if err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("записей %d, хочу 2", len(got))
	}
	want := IndexEntry{
		PkgName:        "0ad",
		PkgVer:         "0ad-0.27.1_6",
		Architecture:   "x86_64",
		ShortDesc:      "GPL licensed RTS, similar to Age of Empires",
		Homepage:       "https://play0ad.com/",
		License:        "GPL-2.0-or-later",
		Maintainer:     "Helmut Pozimski <helmut@example.org> & void",
		FilenameSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FilenameSize:   9157632,
		InstalledSize:  24227840,
		Provides:       []string{"cmd:0ad", "cmd:pyrogenesis"},
		RunDepends:     []string{"glibc>=2.41_1", "libstdc++>=14.2.1_1"},
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("0ad = %+v,\nхочу %+v", got[0], want)
	}

	lib := got[1]
	if lib.PkgName != "libstdc++" || lib.PkgVer != "libstdc++-14.2.1_1~rc1" {
		t.Errorf("libstdc++ имя/версия = %q/%q", lib.PkgName, lib.PkgVer)
	}
	if !reflect.DeepEqual(lib.ShlibProvides, []string{"libstdc++.so.6"}) {
		t.Errorf("shlib-provides = %v", lib.ShlibProvides)
	}
	if !reflect.DeepEqual(lib.ShlibRequires, []string{"libc.so.6", "libgcc_s.so.1"}) {
		t.Errorf("shlib-requires = %v", lib.ShlibRequires)
	}
	if lib.RunDepends != nil {
		t.Errorf("run_depends = %v, хочу nil", lib.RunDepends)
	}
}

func TestParseIndexPlistEmptyArrays(t *testing.T) {
	xml := `<plist><dict><key>empty</key><dict>` +
		`<key>run_depends</key><array></array>` +
		`<key>provides</key><array/>` +
		`</dict></dict></plist>`
	got, err := parseIndex(t, xml)
	if err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("записей %d, хочу 1", len(got))
	}
	if len(got[0].RunDepends) != 0 || len(got[0].Provides) != 0 {
		t.Errorf("пустые массивы = %v/%v", got[0].RunDepends, got[0].Provides)
	}
}

func TestParseIndexPlistUnknownKeys(t *testing.T) {
	// forward-совместимость: чужие ключи (строка, вложенный dict, data)
	// скипаются, соседние известные поля читаются.
	xml := `<plist><dict><key>0ad</key><dict>` +
		`<key>pkgver</key><string>0ad-0.27.1_6</string>` +
		`<key>future-field</key><string>x</string>` +
		`<key>future-dict</key><dict><key>nested</key><string>y</string></dict>` +
		`<key>future-data</key><data>QUFBQQ==</data>` +
		`<key>future-arr</key><array><string>z</string></array>` +
		`<key>short_desc</key><string>RTS</string>` +
		`</dict></dict></plist>`
	got, err := parseIndex(t, xml)
	if err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("записей %d, хочу 1", len(got))
	}
	if got[0].PkgVer != "0ad-0.27.1_6" || got[0].ShortDesc != "RTS" {
		t.Errorf("соседние поля = %q/%q", got[0].PkgVer, got[0].ShortDesc)
	}
}

func TestParseIndexPlistNilArgs(t *testing.T) {
	if err := ParseIndexPlist(nil, func(IndexEntry) error { return nil }); !errors.Is(err, ErrBadPlist) {
		t.Fatalf("nil-источник: ошибка %v, хочу ErrBadPlist", err)
	}
	if err := ParseIndexPlist(strings.NewReader(realIndex), nil); !errors.Is(err, ErrBadPlist) {
		t.Fatalf("nil-колбэк: ошибка %v, хочу ErrBadPlist", err)
	}
}

func TestParseIndexPlistCallbackError(t *testing.T) {
	sentinel := errors.New("стоп")
	err := ParseIndexPlist(strings.NewReader(realIndex), func(IndexEntry) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("ошибка %v, хочу sentinel", err)
	}
}

func TestParseIndexPlistBad(t *testing.T) {
	longString := `<key>short_desc</key><string>` + strings.Repeat("a", maxFieldValue+1) + `</string>`
	bigArray := `<key>run_depends</key><array>` + strings.Repeat(`<string>x</string>`, maxArrayElems+1) + `</array>`
	cases := map[string]string{
		"обрыв посреди dict": `<plist><dict><key>0ad</key><dict>` +
			`<key>pkgver</key><string>0ad-0.27.1_6</string>`,
		"верхний уровень array": `<plist><array><string>x</string></array></plist>`,
		"integer-мусор": `<plist><dict><key>0ad</key><dict>` +
			`<key>filename-size</key><integer>12x</integer></dict></dict></plist>`,
		"integer-переполнение": `<plist><dict><key>0ad</key><dict>` +
			`<key>filename-size</key><integer>99999999999999999999</integer></dict></dict></plist>`,
		"лимит поля": `<plist><dict><key>0ad</key><dict>` + longString +
			`</dict></dict></plist>`,
		"лимит массива": `<plist><dict><key>0ad</key><dict>` + bigArray +
			`</dict></dict></plist>`,
		"значение не dict":       `<plist><dict><key>0ad</key><string>x</string></dict></plist>`,
		"массив массивов":        `<plist><dict><key>0ad</key><dict><key>run_depends</key><array><array></array></array></dict></dict></plist>`,
		"вложенный элемент":      `<plist><dict><key>0ad</key><dict><key>pkgver</key><string><b>x</b></string></dict></dict></plist>`,
		"чужой тип у известного": `<plist><dict><key>0ad</key><dict><key>pkgver</key><integer>1</integer></dict></dict></plist>`,
		"пропущено значение":     `<plist><dict><key>orphan</key></dict></plist>`,
		"битая сущность":         `<plist><dict><key>0ad</key><dict><key>pkgver</key><string>&bogus;</string></dict></dict></plist>`,
		"строка вместо массива":  `<plist><dict><key>0ad</key><dict><key>run_depends</key><string>x</string></dict></dict></plist>`,
		"массив вместо строки":   `<plist><dict><key>0ad</key><dict><key>pkgver</key><array><string>x</string></array></dict></dict></plist>`,
	}
	for name, xml := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseIndex(t, xml)
			if !errors.Is(err, ErrBadPlist) {
				t.Fatalf("ошибка %v, хочу ErrBadPlist", err)
			}
		})
	}
}

// repeatReader бесконечно повторяет unit times раз — генератор лимита
// записей без материализации мегабайт XML в памяти теста.
type repeatReader struct {
	unit  []byte
	times int
	off   int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.times <= 0 {
		return 0, io.EOF
	}
	n := copy(p, r.unit[r.off:])
	r.off += n
	if r.off == len(r.unit) {
		r.off = 0
		r.times--
	}
	return n, nil
}

func TestParseIndexPlistPackageLimit(t *testing.T) {
	const prefix = `<?xml version="1.0"?><plist><dict>`
	const entry = `<key>p</key><dict><key>pkgver</key><string>1</string></dict>`
	const suffix = `</dict></plist>`
	r := io.MultiReader(
		strings.NewReader(prefix),
		&repeatReader{unit: []byte(entry), times: maxPackages + 1},
		strings.NewReader(suffix),
	)
	count := 0
	err := ParseIndexPlist(r, func(IndexEntry) error {
		count++
		return nil
	})
	if !errors.Is(err, ErrBadPlist) {
		t.Fatalf("ошибка %v, хочу ErrBadPlist", err)
	}
	if count != maxPackages {
		t.Errorf("колбэк вызван %d раз, хочу %d", count, maxPackages)
	}
}
