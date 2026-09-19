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
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// roundtripEntries — вход writer'а с РЕАЛЬНЫМИ именами (урок 65): `0ad`,
// `libstdc++` (`+`, `~` в pkgver, `>=` в зависимостях), `Mustache` (верхний
// регистр), `python3-pip` (дефис, noarch). maintainer с `&`/`<`/`>` — проверка
// экранирования stdlib; у Mustache опциональные поля пусты.
func roundtripEntries() []IndexOut {
	return []IndexOut{
		{
			Props: Props{
				PkgName:       "0ad",
				PkgVer:        "0ad-0.27.1_6",
				Version:       "0.27.1",
				Architecture:  "x86_64",
				ShortDesc:     "GPL licensed RTS, similar to Age of Empires",
				Homepage:      "https://play0ad.com/",
				License:       "GPL-2.0-or-later",
				Maintainer:    "A & B <a@b.c>",
				InstalledSize: 24227840,
				RunDepends:    []string{"glibc>=2.41_1", "libstdc++>=14.2.1_1"},
				Provides:      []string{"cmd:0ad", "cmd:pyrogenesis"},
			},
			FilenameSHA256: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			FilenameSize:   9157632,
		},
		{
			Props: Props{
				PkgName:      "libstdc++",
				PkgVer:       "libstdc++-14.2.1_1~rc1",
				Architecture: "x86_64",
				RunDepends:   []string{"libc.so.6", "libgcc_s.so.1"},
			},
			FilenameSize: 2416640,
		},
		{
			Props: Props{
				PkgName:      "Mustache",
				PkgVer:       "Mustache-4.1_1",
				Architecture: "x86_64",
			},
		},
		{
			Props: Props{
				PkgName:      "python3-pip",
				PkgVer:       "python3-pip-24.2_1",
				Architecture: "noarch",
				Provides:     []string{"python3-pip"},
			},
			FilenameSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
}

// roundtripWant — ожидаемый разбор: поля, читаемые ParseIndexPlist (Version и
// SourceRevisions парсером не читаются — forward-совместимость proplib),
// порядок записей — по PkgName (writer сортирует).
func roundtripWant() []IndexEntry {
	return []IndexEntry{
		{
			PkgName:        "0ad",
			PkgVer:         "0ad-0.27.1_6",
			Architecture:   "x86_64",
			ShortDesc:      "GPL licensed RTS, similar to Age of Empires",
			Homepage:       "https://play0ad.com/",
			License:        "GPL-2.0-or-later",
			Maintainer:     "A & B <a@b.c>",
			FilenameSHA256: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			FilenameSize:   9157632,
			InstalledSize:  24227840,
			RunDepends:     []string{"glibc>=2.41_1", "libstdc++>=14.2.1_1"},
			Provides:       []string{"cmd:0ad", "cmd:pyrogenesis"},
		},
		{
			PkgName:      "Mustache",
			PkgVer:       "Mustache-4.1_1",
			Architecture: "x86_64",
		},
		{
			PkgName:      "libstdc++",
			PkgVer:       "libstdc++-14.2.1_1~rc1",
			Architecture: "x86_64",
			FilenameSize: 2416640,
			RunDepends:   []string{"libc.so.6", "libgcc_s.so.1"},
		},
		{
			PkgName:        "python3-pip",
			PkgVer:         "python3-pip-24.2_1",
			Architecture:   "noarch",
			FilenameSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Provides:       []string{"python3-pip"},
		},
	}
}

// parseWrittenIndex — roundtrip-хелпер: пишет entries и разбирает результат
// нашим же парсером (132).
func parseWrittenIndex(t *testing.T, entries []IndexOut) ([]IndexEntry, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteIndexPlist(&buf, entries); err != nil {
		t.Fatalf("WriteIndexPlist: %v", err)
	}
	raw := buf.String()
	var got []IndexEntry
	if err := ParseIndexPlist(strings.NewReader(raw), func(e IndexEntry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	return got, raw
}

// TestWriteIndexPlistRoundtrip: написанное читается собственным парсером без
// потерь (главный контракт writer'а), включая энтити в maintainer.
func TestWriteIndexPlistRoundtrip(t *testing.T) {
	got, raw := parseWrittenIndex(t, roundtripEntries())
	want := roundtripWant()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip = %+v,\nхочу %+v", got, want)
	}
	if !strings.Contains(raw, "&amp;") || !strings.Contains(raw, "&lt;") {
		t.Errorf("энтити не закодированы stdlib: %q", raw)
	}
	if !strings.HasPrefix(raw, xml.Header) {
		t.Errorf("нет xml-шапки: %q", raw[:min(len(raw), 64)])
	}
	if !strings.Contains(raw, "<!DOCTYPE plist PUBLIC") || !strings.Contains(raw, `<plist version="1.0">`) {
		t.Errorf("нет DOCTYPE/<plist version>: %q", raw[:min(len(raw), 128)])
	}
}

// TestWriteIndexPlistDeterministic: две генерации одного набора — байт-в-байт
// (инвариант reindex, сессия 141 повторит это на уровне repodata).
func TestWriteIndexPlistDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := WriteIndexPlist(&a, roundtripEntries()); err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	if err := WriteIndexPlist(&b, roundtripEntries()); err != nil {
		t.Fatalf("второй вызов: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Errorf("вывод не детерминирован:\n%s\n---\n%s", a.String(), b.String())
	}
}

// TestWriteIndexPlistSortsByName: записи идут по алфавиту независимо от
// порядка входа; вход не мутируется.
func TestWriteIndexPlistSortsByName(t *testing.T) {
	entries := roundtripEntries()
	reversed := make([]IndexOut, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		reversed = append(reversed, entries[i])
	}
	got, _ := parseWrittenIndex(t, reversed)
	names := make([]string, 0, len(got))
	for _, e := range got {
		names = append(names, e.PkgName)
	}
	want := []string{"0ad", "Mustache", "libstdc++", "python3-pip"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("порядок = %v, хочу %v", names, want)
	}
	if entries[0].PkgName != "0ad" || entries[3].PkgName != "python3-pip" {
		t.Errorf("вход мутирован: %q…%q", entries[0].PkgName, entries[3].PkgName)
	}
}

// TestWriteIndexPlistLarge: 10k записей пишутся и читаются стримингом без
// накопления всего индекса в памяти (roundtrip-счётчик).
func TestWriteIndexPlistLarge(t *testing.T) {
	const n = 10000
	entries := make([]IndexOut, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, IndexOut{
			Props: Props{
				PkgName:      fmt.Sprintf("pkg-%05d", i),
				PkgVer:       fmt.Sprintf("pkg-%05d-1.0_1", i),
				Architecture: "x86_64",
			},
			FilenameSize: int64(i + 1),
		})
	}
	var count int
	var buf bytes.Buffer
	if err := WriteIndexPlist(&buf, entries); err != nil {
		t.Fatalf("WriteIndexPlist: %v", err)
	}
	if err := ParseIndexPlist(strings.NewReader(buf.String()), func(IndexEntry) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	if count != n {
		t.Errorf("записей %d, хочу %d", count, n)
	}
}

// TestWriteIndexPlistNilWriter: nil-приёмник — контракт nil-источника парсера.
func TestWriteIndexPlistNilWriter(t *testing.T) {
	if err := WriteIndexPlist(nil, nil); err == nil {
		t.Fatal("nil-приёмник не дал ошибку")
	}
}
