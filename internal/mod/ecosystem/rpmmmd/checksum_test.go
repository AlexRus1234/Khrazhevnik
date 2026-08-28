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

// Таблица чексумм rpm-md: Enumerate собирает checksum каждого <data>
// repomd.xml (репозиториев dnf/zypper) по location, Resolve выдаёт их
// в Target — движок кеша верифицирует скачанные repodata. Чексуммы
// пакетов из primary.xml в v1 не верифицируются (не-цель, задокументировано).

package rpmmmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

const testRepomdChecksums = `<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <checksum type="sha256">abc123def456abc123def456abc123def456abc123def456abc123def456abcd</checksum>
    <location href="repodata/primary.xml.gz"/>
  </data>
  <data type="filelists">
    <checksum type="md5">0123456789abcdef0123456789abcdef</checksum>
    <location href="repodata/filelists.xml.gz"/>
  </data>
  <data type="other">
    <checksum type="weird-320">cafebabe</checksum>
    <location href="repodata/other.xml.gz"/>
  </data>
</repomd>
`

const testPrimaryOne = `<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common">
  <package type="rpm">
    <name>foo</name>
    <location href="Packages/f/foo-1.0-1.x86_64.rpm"/>
  </package>
</metadata>
`

func newChecksumAdapter(t *testing.T, r domain.Remote) (*Adapter, domain.Remote) {
	t.Helper()
	store := testutil.NewFakeRemoteStore()
	created, err := store.CreateRemote(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(store, testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a, created
}

func TestResolveRepodataChecksumsAfterEnumerate(t *testing.T) {
	remote := domain.Remote{
		Name: "fedora", Ecosystem: Name, BaseURL: "https://mirrors.example/fedora",
		Mode: domain.ModeMirror, Enabled: true,
	}
	a, remote := newChecksumAdapter(t, remote)

	// До Enumerate чексумм нет.
	target, ok := a.Resolve("/rpm/fedora/repodata/primary.xml.gz")
	if !ok {
		t.Fatal("Resolve repodata = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("без sync чексуммы быть не должно: %+v", target.Checksum)
	}

	// primary в repomd — .xml.gz (как у настоящих репозиториев):
	// Enumerate тянет его по location-href и сам распаковывает gzip.
	meta := fakeMeta{files: map[string][]byte{
		"/rpm/fedora/repodata/repomd.xml":  []byte(testRepomdChecksums),
		"/rpm/fedora/repodata/primary.xml.gz": gzBytes(t, testPrimaryOne),
	}}
	if _, err := a.Enumerate(context.Background(), remote, meta); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	// checksum каждого <data> привязан к его location с алгоритмом
	// из атрибута type.
	target, ok = a.Resolve("/rpm/fedora/repodata/primary.xml.gz")
	if !ok {
		t.Fatal("Resolve primary = false")
	}
	want := "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	if target.Checksum.Algo != "sha256" || target.Checksum.Hex != want {
		t.Fatalf("Checksum primary = %+v, хочу sha256 %s", target.Checksum, want)
	}
	target, ok = a.Resolve("/rpm/fedora/repodata/filelists.xml.gz")
	if !ok {
		t.Fatal("Resolve filelists = false")
	}
	if target.Checksum.Algo != "md5" || target.Checksum.Hex != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("Checksum filelists = %+v", target.Checksum)
	}
	// неизвестный алгоритм — верифицировать нечем, записи нет.
	target, ok = a.Resolve("/rpm/fedora/repodata/other.xml.gz")
	if !ok {
		t.Fatal("Resolve other = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("чексумма с неизвестным алгоритмом просочилась: %+v", target.Checksum)
	}
	// пакеты из primary в v1 не верифицируются (не-цель).
	target, ok = a.Resolve("/rpm/fedora/Packages/f/foo-1.0-1.x86_64.rpm")
	if !ok {
		t.Fatal("Resolve пакета = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("у пакета не должно быть чексуммы в v1: %+v", target.Checksum)
	}
}

func TestParseRepomdChecksumType(t *testing.T) {
	// алгоритм живёт в атрибуте type элемента <checksum>.
	els := 0
	for el, err := range ParseRepomd(strings.NewReader(testRepomdChecksums)) {
		if err != nil {
			t.Fatalf("ParseRepomd: %v", err)
		}
		if el.Type == "primary" {
			if el.ChecksumType != "sha256" {
				t.Fatalf("ChecksumType = %q, хочу sha256", el.ChecksumType)
			}
			els++
		}
	}
	if els != 1 {
		t.Fatalf("primary-элементов = %d, хочу 1", els)
	}
}

// gzBytes — gzip-упаковка fixture (Enumarate тянет primary как .gz).
func gzBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
