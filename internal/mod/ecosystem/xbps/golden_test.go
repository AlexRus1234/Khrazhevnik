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
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// goldenRepodata — скомпилированный контейнер repodata (zstd+tar),
// коммитится как бинарный артефакт. Пересборка — TestRepoDataGoldenRegen
// (переменная окружения KHRZ_WRITE_GOLDEN=1): фикстура не должна
// собираться в рантайме, иначе golden-тест перестанет ловить дрейф
// формата (парсер и генератор — один код).
const goldenRepodata = "testdata/repodata-golden.zst"

// goldenIndexXML — живой срез x86_64-индекса с РЕАЛЬНЫМИ именами (урок
// 65): 0ad, libstdc++ (`~` в версии, `+` в имени), libxml2,
// python3-pip (noarch, дефис в имени), Mustache. maintainer с энтити
// `&lt;`/`&amp;`, значения с `&gt;=`, filename-sha256 в верхнем и нижнем
// регистре (парсер обязан сохранить регистр байт-в-байт — это имя файла).
const goldenIndexXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>0ad</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>filename-sha256</key>
		<string>E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855</string>
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
		<key>filename-size</key>
		<integer>2416640</integer>
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
	<key>libxml2</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>filename-sha256</key>
		<string>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</string>
		<key>filename-size</key>
		<integer>1310720</integer>
		<key>installed_size</key>
		<integer>5242880</integer>
		<key>pkgver</key>
		<string>libxml2-2.13.4_1</string>
		<key>short_desc</key>
		<string>XML C parser and toolkit</string>
	</dict>
	<key>python3-pip</key>
	<dict>
		<key>architecture</key>
		<string>noarch</string>
		<key>pkgver</key>
		<string>python3-pip-24.2_1</string>
		<key>run_depends</key>
		<array>
			<string>python3&gt;=3.12.0_1</string>
		</array>
	</dict>
	<key>Mustache</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>pkgver</key>
		<string>Mustache-4.1_1</string>
	</dict>
</dict>
</plist>
`

// goldenMetaXML — index-meta.plist с публичным ключом: data-элемент
// (base64) — вход сессий 139/141 (TOFU-импорт ключа клиентом), наш
// парсер его не разбирает, closeFn отдаёт байты как есть.
const goldenMetaXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>public-key</key>
	<data>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</data>
	<key>public-key-size</key>
	<integer>32</integer>
</dict>
</plist>
`

// goldenEntries — ожидаемая Go-таблица: все поля IndexEntry, включая
// порядок и состав массивов и регистр FilenameSHA256.
var goldenEntries = []IndexEntry{
	{
		PkgName:        "0ad",
		PkgVer:         "0ad-0.27.1_6",
		Architecture:   "x86_64",
		ShortDesc:      "GPL licensed RTS, similar to Age of Empires",
		Homepage:       "https://play0ad.com/",
		License:        "GPL-2.0-or-later",
		Maintainer:     "Helmut Pozimski <helmut@example.org> & void",
		FilenameSHA256: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
		FilenameSize:   9157632,
		InstalledSize:  24227840,
		RunDepends:     []string{"glibc>=2.41_1", "libstdc++>=14.2.1_1"},
		Provides:       []string{"cmd:0ad", "cmd:pyrogenesis"},
	},
	{
		PkgName:       "libstdc++",
		PkgVer:        "libstdc++-14.2.1_1~rc1",
		Architecture:  "x86_64",
		FilenameSize:  2416640,
		ShlibProvides: []string{"libstdc++.so.6"},
		ShlibRequires: []string{"libc.so.6", "libgcc_s.so.1"},
	},
	{
		PkgName:        "libxml2",
		PkgVer:         "libxml2-2.13.4_1",
		Architecture:   "x86_64",
		ShortDesc:      "XML C parser and toolkit",
		FilenameSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FilenameSize:   1310720,
		InstalledSize:  5242880,
	},
	{
		PkgName:      "python3-pip",
		PkgVer:       "python3-pip-24.2_1",
		Architecture: "noarch",
		RunDepends:   []string{"python3>=3.12.0_1"},
	},
	{
		PkgName:      "Mustache",
		PkgVer:       "Mustache-4.1_1",
		Architecture: "x86_64",
	},
}

// TestRepoDataGolden: полная композиция OpenRepoData → ParseIndexPlist
// на скомпилированном testdata-контейнере даёт ожидаемые поля.
func TestRepoDataGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(goldenRepodata))
	if err != nil {
		t.Fatalf("чтение %s: %v", goldenRepodata, err)
	}
	index, closeFn, err := OpenRepoData(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	var got []IndexEntry
	if err := ParseIndexPlist(index, func(e IndexEntry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	if _, err := closeFn(); err != nil {
		t.Fatalf("closeFn: %v", err)
	}
	if !reflect.DeepEqual(got, goldenEntries) {
		t.Errorf("записи = %+v,\nхочу %+v", got, goldenEntries)
	}
}

// TestRepoDataGoldenMeta: closeFn возвращает index-meta.plist с
// data-элементом public-key (base64) — байты для сессий 139/141.
func TestRepoDataGoldenMeta(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(goldenRepodata))
	if err != nil {
		t.Fatalf("чтение %s: %v", goldenRepodata, err)
	}
	index, closeFn, err := OpenRepoData(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	if _, err := io.Copy(io.Discard, index); err != nil {
		t.Fatalf("чтение index: %v", err)
	}
	meta, err := closeFn()
	if err != nil {
		t.Fatalf("closeFn: %v", err)
	}
	if !bytes.Contains(meta, []byte("<key>public-key</key>")) {
		t.Errorf("meta без ключа public-key: %q", meta)
	}
	if !bytes.Contains(meta, []byte("<data>")) {
		t.Errorf("meta без data-элемента: %q", meta)
	}
	const b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("декодирование ожидаемого ключа: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("ключ %d байт, хочу 32", len(key))
	}
	if !bytes.Contains(meta, []byte(b64)) {
		t.Errorf("meta без ожидаемого base64-ключа %q", b64)
	}
}

// TestRepoDataGoldenRegen пересобирает testdata-контейнер из констант
// golden_test.go. Запуск только вручную (KHRZ_WRITE_GOLDEN=1) — в CI и
// обычном прогоне пропускается: артефакт коммитится.
func TestRepoDataGoldenRegen(t *testing.T) {
	if os.Getenv("KHRZ_WRITE_GOLDEN") == "" {
		t.Skip("пересборка golden: KHRZ_WRITE_GOLDEN=1 go test -run TestRepoDataGoldenRegen")
	}
	raw := newRepoZstd(t,
		tarFile{indexName, []byte(goldenIndexXML)},
		tarFile{metaName, []byte(goldenMetaXML)},
		tarFile{stageName, nil},
	)
	if len(raw) > 16<<10 {
		t.Fatalf("контейнер %d байт превышает 16 KiB", len(raw))
	}
	if err := os.MkdirAll(filepath.Dir(goldenRepodata), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(goldenRepodata), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
