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

// Таблица чексумм apk: Enumerate собирает SHA1 из поля C: APKINDEX,
// Resolve выдаёт их в Target — движок кеша верифицирует скачивание
// .apk. Без sync чексумм нет — честная деградация.

package apk

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

// TestCsumFromIndex — формат apk-tools: «Q1» + base64 raw SHA1.
func TestCsumFromIndex(t *testing.T) {
	digest := sha1.Sum([]byte("alpine package bytes"))
	csum := "Q1" + base64.StdEncoding.EncodeToString(digest[:])

	got, ok := csumFromIndex(csum)
	if !ok {
		t.Fatalf("csumFromIndex(%q) = не ок", csum)
	}
	if got.Algo != "sha1" || got.Hex != fmt.Sprintf("%x", digest) {
		t.Fatalf("Checksum = %+v, хочу sha1 %x", got, digest)
	}

	// без паддинга — apk-сборки бывают разные
	raw, ok := csumFromIndex("Q1" + base64.RawStdEncoding.EncodeToString(digest[:]))
	if !ok || raw.Hex != got.Hex {
		t.Fatalf("base64 без паддинга не разобран: %+v, %v", raw, ok)
	}

	for _, bad := range []string{
		"",              // пусто
		"deadbeef",      // не «Q1»-формат
		"Q2" + csum[2:], // неизвестный алгоритм
		"Q1не-base64!",  // битый base64
		"Q1" + base64.StdEncoding.EncodeToString([]byte("коротыш")), // не 20 байт
	} {
		if sum, ok := csumFromIndex(bad); ok {
			t.Errorf("csumFromIndex(%q) = %+v, хочу отказ", bad, sum)
		}
	}
}

func TestResolveApkChecksumsAfterEnumerate(t *testing.T) {
	digest := sha1.Sum([]byte("foo apk bytes"))
	goodCsum := "Q1" + base64.StdEncoding.EncodeToString(digest[:])
	indexText := []byte(
		"P:foo\nV:1.0-r0\nC:" + goodCsum + "\nF:x86_64/foo-1.0-r0.apk\n\n" +
			"P:nohash\nV:2.0-r0\nF:x86_64/nohash-2.0-r0.apk\n\n" +
			"P:garbage\nV:3.0-r0\nC:Q1мусор\nF:x86_64/garbage-3.0-r0.apk\n\n")
	indexTarGz := newTarGz(t, tarEntries{"APKINDEX": indexText})

	remote := domain.Remote{
		Name: "alpine", Ecosystem: Name, BaseURL: "https://dl-cdn.alpinelinux.org/alpine",
		Enabled: true, Include: []string{"x86_64"},
	}
	store := testutil.NewFakeRemoteStore()
	created, err := store.CreateRemote(context.Background(), remote)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(store, testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}

	// До Enumerate чексумм нет.
	target, ok := a.Resolve("/apk/alpine/x86_64/foo-1.0-r0.apk")
	if !ok {
		t.Fatal("Resolve = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("без sync чексуммы быть не должно: %+v", target.Checksum)
	}

	meta := fakeMeta{files: map[string][]byte{
		"/apk/alpine/x86_64/APKINDEX.tar.gz": indexTarGz,
	}}
	if _, err := a.Enumerate(context.Background(), created, meta); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	target, ok = a.Resolve("/apk/alpine/x86_64/foo-1.0-r0.apk")
	if !ok {
		t.Fatal("Resolve пакета = false")
	}
	if target.Checksum.Algo != "sha1" || target.Checksum.Hex != fmt.Sprintf("%x", digest) {
		t.Fatalf("Checksum = %+v, хочу sha1 %x", target.Checksum, digest)
	}
	// запись без C: и с битым C: — чексуммы нет.
	for _, p := range []string{
		"/apk/alpine/x86_64/nohash-2.0-r0.apk",
		"/apk/alpine/x86_64/garbage-3.0-r0.apk",
	} {
		target, ok = a.Resolve(p)
		if !ok {
			t.Fatalf("Resolve %s = false", p)
		}
		if target.Checksum.Algo != "" {
			t.Fatalf("%s: чексумма не ожидается: %+v", p, target.Checksum)
		}
	}
}
