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
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"khrazhevnik/internal/core/domain"
)

// fakeMeta — MetaFetcher, отдающий предзагруженные байты по пути.
type fakeMeta struct {
	files map[string][]byte
}

func (m fakeMeta) Fetch(_ context.Context, ecosystemPath string) (io.ReadCloser, error) {
	b, ok := m.files[ecosystemPath]
	if !ok {
		return nil, &domain.NotFoundError{What: "upstream метаданные", Key: ecosystemPath}
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// enumShaGood — валидный lowercase-совместимый SHA256 (верхний регистр
// специально: sha256Checksum обязан нормализовать).
const enumShaGood = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

// enumIndexX86 — срез x86_64-индекса с реальными именами (урок 65):
// 0ad (валидный sha), libstdc++ («+»/«~», битый sha), python3-pip
// (noarch, sha нет).
const enumIndexX86 = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>0ad</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>filename-sha256</key>
		<string>` + enumShaGood + `</string>
		<key>pkgver</key>
		<string>0ad-0.27.1_6</string>
	</dict>
	<key>libstdc++</key>
	<dict>
		<key>architecture</key>
		<string>x86_64</string>
		<key>filename-sha256</key>
		<string>deadbeef</string>
		<key>pkgver</key>
		<string>libstdc++-14.2.1_1~rc1</string>
	</dict>
	<key>python3-pip</key>
	<dict>
		<key>architecture</key>
		<string>noarch</string>
		<key>pkgver</key>
		<string>python3-pip-24.2_1</string>
	</dict>
</dict>
</plist>
`

// enumIndexAarch64 — aarch64-индекс: свой пакет + тот же noarch
// (в xbps noarch входит в каждый arch-индекс — дедуп обязателен).
const enumIndexAarch64 = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Mustache</key>
	<dict>
		<key>architecture</key>
		<string>aarch64</string>
		<key>filename-sha256</key>
		<string>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</string>
		<key>pkgver</key>
		<string>Mustache-4.1_1</string>
	</dict>
	<key>python3-pip</key>
	<dict>
		<key>architecture</key>
		<string>noarch</string>
		<key>pkgver</key>
		<string>python3-pip-24.2_1</string>
	</dict>
</dict>
</plist>
`

// enumRepodata собирает zstd+tar-контейнер repodata из index.plist
// (meta — golden, stage — пустой), как публикует Void.
func enumRepodata(t *testing.T, indexXML string) []byte {
	t.Helper()
	return newRepoZstd(t,
		tarFile{indexName, []byte(indexXML)},
		tarFile{metaName, []byte(goldenMetaXML)},
		tarFile{stageName, nil},
	)
}

// enumRemote — remote с включёнными архитектурами для Enumerate.
func enumRemote(include ...string) domain.Remote {
	return domain.Remote{
		ID: 9, Name: "void", Ecosystem: Name,
		BaseURL: "https://repo-default.voidlinux.org/current",
		Enabled: true, Include: include,
	}
}

// enumMeta — MetaFetcher с индексами обеих архитектур.
func enumMeta(t *testing.T) fakeMeta {
	t.Helper()
	return fakeMeta{files: map[string][]byte{
		"/xbps/void/x86_64-repodata":  enumRepodata(t, enumIndexX86),
		"/xbps/void/aarch64-repodata": enumRepodata(t, enumIndexAarch64),
	}}
}

func TestEnumerateXbpsSingleArch(t *testing.T) {
	a := newResolveAdapter(t, enumRemote("x86_64"))
	got, err := a.Enumerate(context.Background(), enumRemote("x86_64"), enumMeta(t))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	want := []string{
		"/0ad-0.27.1_6.x86_64.xbps",
		"/libstdc++-14.2.1_1~rc1.x86_64.xbps",
		"/python3-pip-24.2_1.noarch.xbps",
		"/0ad-0.27.1_6.x86_64.xbps.sig2",
		"/libstdc++-14.2.1_1~rc1.x86_64.xbps.sig2",
		"/python3-pip-24.2_1.noarch.xbps.sig2",
	}
	assertPathSet(t, got, want)
}

func TestEnumerateXbpsMultiArchNoarchDedup(t *testing.T) {
	a := newResolveAdapter(t, enumRemote("x86_64", "aarch64"))
	got, err := a.Enumerate(context.Background(), enumRemote("x86_64", "aarch64"), enumMeta(t))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	// noarch-пакет входит в оба индекса, но в результате — один раз.
	if n := countPath(got, "/python3-pip-24.2_1.noarch.xbps"); n != 1 {
		t.Errorf("noarch .xbps встречается %d раз, хочу 1", n)
	}
	if n := countPath(got, "/python3-pip-24.2_1.noarch.xbps.sig2"); n != 1 {
		t.Errorf("noarch .sig2 встречается %d раз, хочу 1", n)
	}
	for _, p := range []string{
		"/0ad-0.27.1_6.x86_64.xbps",
		"/Mustache-4.1_1.aarch64.xbps",
	} {
		if countPath(got, p) != 1 {
			t.Errorf("путь %q не найден ровно один раз", p)
		}
	}
}

func TestEnumerateXbpsPackageSigPairs(t *testing.T) {
	a := newResolveAdapter(t, enumRemote("x86_64"))
	got, err := a.Enumerate(context.Background(), enumRemote("x86_64"), enumMeta(t))
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	set := make(map[string]struct{}, len(got))
	for _, p := range got {
		set[p] = struct{}{}
	}
	for p := range set {
		base, ok := strings.CutSuffix(p, ".sig2")
		switch {
		case ok:
			if !strings.HasSuffix(base, ".xbps") {
				t.Errorf("подпись %q не от .xbps-пакета", p)
			}
			if _, ok := set[base]; !ok {
				t.Errorf("подпись %q без пакета %q", p, base)
			}
		case strings.HasSuffix(p, ".xbps"):
			if _, ok := set[p+".sig2"]; !ok {
				t.Errorf("пакет %q без подписи %q", p, p+".sig2")
			}
		default:
			t.Errorf("путь %q не пакет и не .sig2", p)
		}
	}
}

func TestEnumerateXbpsErrors(t *testing.T) {
	a := newResolveAdapter(t, enumRemote("x86_64"))
	t.Run("пустой Include — ValidationError", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), enumRemote(), enumMeta(t))
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу *ValidationError", err)
		}
	})
	t.Run("repodata отсутствует — NotFound", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), enumRemote("x86_64"), fakeMeta{})
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу *NotFoundError", err)
		}
	})
	t.Run("nil MetaFetcher — ошибка", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), enumRemote("x86_64"), nil)
		if err == nil {
			t.Fatal("nil MetaFetcher должен ошибаться")
		}
	})
}

func TestResolveXbpsChecksumsAfterEnumerate(t *testing.T) {
	a := newResolveAdapter(t, enumRemote("x86_64"))
	if _, err := a.Enumerate(context.Background(), enumRemote("x86_64"), enumMeta(t)); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	target, ok := a.Resolve("/xbps/void/0ad-0.27.1_6.x86_64.xbps")
	if !ok {
		t.Fatal("Resolve пакета = false")
	}
	wantHex := strings.ToLower(enumShaGood)
	if target.Checksum.Algo != "sha256" || target.Checksum.Hex != wantHex {
		t.Fatalf("Checksum = %+v, хочу sha256 %s", target.Checksum, wantHex)
	}

	// битый/отсутствующий sha256 и `.sig2` — чексуммы нет (деградация).
	for _, p := range []string{
		"/xbps/void/libstdc++-14.2.1_1~rc1.x86_64.xbps",
		"/xbps/void/python3-pip-24.2_1.noarch.xbps",
		"/xbps/void/0ad-0.27.1_6.x86_64.xbps.sig2",
	} {
		target, ok = a.Resolve(p)
		if !ok {
			t.Fatalf("Resolve %s = false", p)
		}
		if target.Checksum.Algo != "" {
			t.Errorf("%s: чексуммы не ожидается: %+v", p, target.Checksum)
		}
	}
}

func TestEnumerateXbpsFetchErrorKeepsChecksums(t *testing.T) {
	a := newResolveAdapter(t, enumRemote("x86_64", "aarch64"))
	full := enumRemote("x86_64", "aarch64")
	if _, err := a.Enumerate(context.Background(), full, enumMeta(t)); err != nil {
		t.Fatalf("первый Enumerate: %v", err)
	}
	// Ошибка на aarch64: частичный проход не должен заменять таблицу
	// чексумм — Resolve продолжает сверять x86_64-пакеты.
	broken := fakeMeta{files: map[string][]byte{
		"/xbps/void/x86_64-repodata": enumRepodata(t, enumIndexX86),
	}}
	if _, err := a.Enumerate(context.Background(), full, broken); err == nil {
		t.Fatal("Enumerate с отсутствующим aarch64-индексом должен ошибаться")
	}
	target, ok := a.Resolve("/xbps/void/0ad-0.27.1_6.x86_64.xbps")
	if !ok {
		t.Fatal("Resolve = false")
	}
	if target.Checksum.Algo != "sha256" {
		t.Fatalf("таблица чексумм затёрта частичным sync: %+v", target.Checksum)
	}

	// Свежий адаптер: упавший Enumerate не оставляет никаких чексумм.
	fresh := newResolveAdapter(t, enumRemote("x86_64", "aarch64"))
	if _, err := fresh.Enumerate(context.Background(), full, broken); err == nil {
		t.Fatal("Enumerate (fresh) должен ошибаться")
	}
	target, ok = fresh.Resolve("/xbps/void/0ad-0.27.1_6.x86_64.xbps")
	if !ok {
		t.Fatal("Resolve (fresh) = false")
	}
	if target.Checksum.Algo != "" {
		t.Fatalf("упавший sync оставил чексуммы: %+v", target.Checksum)
	}
}

func TestParseXbpsInclude(t *testing.T) {
	cases := []struct {
		name    string
		include []string
		wantN   int
		wantErr bool
	}{
		{"одна arch", []string{"x86_64"}, 1, false},
		{"несколько", []string{"x86_64", "aarch64"}, 2, false},
		{"пусто", nil, 0, true},
		{"пустой элемент", []string{""}, 0, true},
		{"со слэшем", []string{"x86_64/extra"}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseXbpsInclude(tc.include)
			if tc.wantErr {
				if err == nil {
					t.Fatal("хочу ошибку, получил nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("не ждал ошибку: %v", err)
			}
			if len(got) != tc.wantN {
				t.Errorf("len = %d, хочу %d", len(got), tc.wantN)
			}
		})
	}
}

// assertPathSet сверяет got с want как множества (порядок не важен) и
// ловит дубли.
func assertPathSet(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Enumerate = %+v (len %d), хочу %+v (len %d)", got, len(got), want, len(want))
	}
	set := make(map[string]int, len(got))
	for _, p := range got {
		set[p]++
	}
	for _, p := range want {
		if set[p] == 0 {
			t.Errorf("путь %q отсутствует", p)
		}
	}
	for p, n := range set {
		if n != 1 {
			t.Errorf("путь %q встречается %d раз", p, n)
		}
	}
}

// countPath считает вхождения пути.
func countPath(paths []string, p string) int {
	n := 0
	for _, got := range paths {
		if got == p {
			n++
		}
	}
	return n
}
