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

// Таблица чексумм: Enumerate (sync зеркала) собирает SHA256 из stanza
// Packages, Resolve выдаёт их в Target — движок кеша верифицирует
// скачивание. Без sync чексумм нет — честная деградация.

package apt

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"khrazhevnik/internal/core/domain"
)

func TestResolveChecksumEmptyBeforeEnumerate(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 1, Name: "debian", BaseURL: "https://deb.debian.org/debian", Enabled: true,
	})
	target, ok := a.Resolve("/apt/debian/pool/main/a/app/app_1.0_amd64.deb")
	if !ok {
		t.Fatal("Resolve = false")
	}
	if target.Checksum.Algo != "" || target.Checksum.Hex != "" {
		t.Fatalf("без sync у Target чексумма быть не должна: %+v", target.Checksum)
	}
}

func TestEnumeratePopulatesChecksums(t *testing.T) {
	remote := domain.Remote{
		ID: 9, Name: "debian", Ecosystem: Name, BaseURL: "https://deb.debian.org/debian",
		Enabled: true, Include: []string{"stable/main"},
	}
	a := newResolveAdapter(t, remote)

	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("app deb bytes")))
	pkg := "Package: app\nFilename: pool/main/a/app/app_1.0_amd64.deb\nSHA256: " + sum + "\n\n" +
		"Package: nohash\nFilename: pool/main/n/no/no_1.0_amd64.deb\n\n" +
		"Package: garbage\nFilename: pool/main/g/garbage/garbage_1.0_amd64.deb\nSHA256: совсем-не-хекс\n\n"
	meta := fakeMeta{files: map[string][]byte{
		"/apt/debian/dists/stable/Release":                    mustReadTestdata(t, "Release.golden"),
		"/apt/debian/dists/stable/main/binary-amd64/Packages": []byte(pkg),
		"/apt/debian/dists/stable/main/binary-arm64/Packages": []byte(pkg),
	}}
	if _, err := a.Enumerate(context.Background(), remote, meta); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	target, ok := a.Resolve("/apt/debian/pool/main/a/app/app_1.0_amd64.deb")
	if !ok {
		t.Fatal("Resolve пакета = false")
	}
	if target.Checksum.Algo != "sha256" || target.Checksum.Hex != sum {
		t.Fatalf("Checksum = %+v, хочу sha256 %s", target.Checksum, sum)
	}

	// stanza без SHA256 — чексуммы нет (честная деградация).
	target, ok = a.Resolve("/apt/debian/pool/main/n/no/no_1.0_amd64.deb")
	if !ok {
		t.Fatal("Resolve пакета без хеша = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("для пакета без SHA256 чексумма не ожидается: %+v", target.Checksum)
	}

	// мусорный hex не попадает в таблицу — иначе каждый запрос
	// превратился бы в вечный checksum mismatch.
	target, ok = a.Resolve("/apt/debian/pool/main/g/garbage/garbage_1.0_amd64.deb")
	if !ok {
		t.Fatal("Resolve пакета с битым хешем = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("мусорный hex просочился в таблицу: %+v", target.Checksum)
	}
}

func TestHexChecksum(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"abc123", "abc123", true},
		{"ABC123", "abc123", true}, // регистр индекса нормализуется
		{" abc123 ", "abc123", true},
		{"", "", false},
		{"   ", "", false},
		{"не-хекс", "", false},
		{"0x1234", "", false},
	}
	for _, tc := range cases {
		got, ok := hexChecksum("sha256", tc.in)
		if ok != tc.ok {
			t.Errorf("hexChecksum(%q) ok = %v, хочу %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got.Hex != tc.want {
			t.Errorf("hexChecksum(%q).Hex = %q, хочу %q", tc.in, got.Hex, tc.want)
		}
	}
}
