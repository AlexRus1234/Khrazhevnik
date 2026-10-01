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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// mustachePropsXML — props.plist живого пакета Mustache (Void x86_64):
// словарь полей, maintainer с энтити `&lt;`/`&amp;` (раскодирует stdlib),
// значения с `&gt;=`. Реальные имена — урок 65.
const mustachePropsXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>pkgname</key>
	<string>Mustache</string>
	<key>pkgver</key>
	<string>Mustache-4.1_1</string>
	<key>version</key>
	<string>4.1_1</string>
	<key>architecture</key>
	<string>x86_64</string>
	<key>short_desc</key>
	<string>Logic-less template engine</string>
	<key>homepage</key>
	<string>https://mustache.github.io/</string>
	<key>license</key>
	<string>MIT</string>
	<key>maintainer</key>
	<string>Helmut Pozimski &lt;helmut@example.org&gt; &amp; void</string>
	<key>installed_size</key>
	<integer>40960</integer>
	<key>source-revisions</key>
	<string>Mustache:1</string>
	<key>run_depends</key>
	<array>
		<string>libc&gt;=0.38_1</string>
	</array>
	<key>provides</key>
	<array>
		<string>Mustache-4.1_1</string>
	</array>
</dict>
</plist>
`

var mustacheProps = Props{
	PkgName:         "Mustache",
	PkgVer:          "Mustache-4.1_1",
	Version:         "4.1_1",
	Architecture:    "x86_64",
	ShortDesc:       "Logic-less template engine",
	Homepage:        "https://mustache.github.io/",
	License:         "MIT",
	Maintainer:      "Helmut Pozimski <helmut@example.org> & void",
	InstalledSize:   40960,
	SourceRevisions: "Mustache:1",
	RunDepends:      []string{"libc>=0.38_1"},
	Provides:        []string{"Mustache-4.1_1"},
}

// tarMember — член tar для сборки тестового пакета: имя пишется как у
// xbps-create (канонический префикс «./»).
type tarMember struct {
	name string
	body []byte
}

// writeTarPkg собирает tar-пакет (формат .xbps) в w.
func writeTarPkg(w io.Writer, members []tarMember) error {
	tw := tar.NewWriter(w)
	for _, m := range members {
		hdr := tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(&hdr); err != nil {
			return err
		}
		if _, err := tw.Write(m.body); err != nil {
			return err
		}
	}
	return tw.Close()
}

// buildTarPkg — writeTarPkg для тестов.
func buildTarPkg(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeTarPkg(&buf, members); err != nil {
		t.Fatalf("writeTarPkg: %v", err)
	}
	return buf.Bytes()
}

// tarHeaderRaw — 512-байтный ustar-заголовок члена с декларированным
// размером и корректной контрольной суммой, БЕЗ тела. Нужен там, где
// тело материализовать нельзя (кап 1 MiB, бомба > 1 GiB): контракт —
// реакция на размер из заголовка, а не на содержимое.
func tarHeaderRaw(name string, size int64) []byte {
	hdr := make([]byte, 512)
	copy(hdr[0:100], name)
	copy(hdr[100:108], "0000644\x00")
	copy(hdr[108:116], "0000000\x00")
	copy(hdr[116:124], "0000000\x00")
	copy(hdr[124:136], fmt.Sprintf("%011s", strconv.FormatInt(size, 8)))
	copy(hdr[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		hdr[i] = ' ' // контрольная сумма считается по пробелам в поле
	}
	hdr[156] = '0' // typeflag: регулярный файл
	copy(hdr[257:263], "ustar\x00")
	copy(hdr[263:265], "00")
	var sum int64
	for _, b := range hdr {
		sum += int64(b)
	}
	copy(hdr[148:156], fmt.Sprintf("%06s\x00 ", strconv.FormatInt(sum, 8)))
	return hdr
}

// compressPackage оборачивает raw tar в выбранную компрессию.
func compressPackage(t *testing.T, kind string, raw []byte) []byte {
	t.Helper()
	switch kind {
	case "raw":
		return raw
	case "zstd":
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatalf("zstd.NewWriter: %v", err)
		}
		if _, err := zw.Write(raw); err != nil {
			t.Fatalf("zstd write: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("zstd close: %v", err)
		}
		return buf.Bytes()
	case "gzip":
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(raw); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		return buf.Bytes()
	default:
		t.Fatalf("неизвестная компрессия %q", kind)
		return nil
	}
}

func TestOpenPackageMustache(t *testing.T) {
	raw := buildTarPkg(t,
		tarMember{"./props.plist", []byte(mustachePropsXML)},
		tarMember{"./files.plist", []byte("<plist><dict></dict></plist>")},
		tarMember{"payload/bin", []byte("MZ")},
	)
	for _, kind := range []string{"raw", "zstd", "gzip"} {
		t.Run(kind, func(t *testing.T) {
			got, err := OpenPackage(bytes.NewReader(compressPackage(t, kind, raw)))
			if err != nil {
				t.Fatalf("OpenPackage: %v", err)
			}
			if !reflect.DeepEqual(got, mustacheProps) {
				t.Errorf("props = %+v,\nхочу %+v", got, mustacheProps)
			}
		})
	}
}

// TestOpenPackagePropsNamePrefix: наш член — ровно «./props.plist»
// (канонический префикс xbps-create). Имя без префикса — чужой член:
// пропускается, пакета с метаданными в архиве нет.
func TestOpenPackagePropsNamePrefix(t *testing.T) {
	t.Run("./props.plist", func(t *testing.T) {
		raw := buildTarPkg(t, tarMember{"./props.plist", []byte(mustachePropsXML)})
		got, err := OpenPackage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("OpenPackage: %v", err)
		}
		if !reflect.DeepEqual(got, mustacheProps) {
			t.Errorf("props = %+v,\nхочу %+v", got, mustacheProps)
		}
	})
	t.Run("props.plist", func(t *testing.T) {
		raw := buildTarPkg(t, tarMember{"props.plist", []byte(mustachePropsXML)})
		if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrPropsMissing) {
			t.Fatalf("ошибка %v, хочу ErrPropsMissing", err)
		}
	})
}

// countingReader считает прочитанные байты: проверка skip'а payload.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestOpenPackageSkipsPayloadBeforeProps: payload до props.plist
// скипается стримингом, файл дочитывается, счётчик ≤ капа.
func TestOpenPackageSkipsPayloadBeforeProps(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 3<<20)
	raw := buildTarPkg(t,
		tarMember{"./files.plist", payload},
		tarMember{"./props.plist", []byte(mustachePropsXML)},
	)
	cr := &countingReader{r: bytes.NewReader(raw)}
	got, err := OpenPackage(cr)
	if err != nil {
		t.Fatalf("OpenPackage: %v", err)
	}
	if !reflect.DeepEqual(got, mustacheProps) {
		t.Errorf("props = %+v,\nхочу %+v", got, mustacheProps)
	}
	// 512 (блок заголовка tar) + тело пропущенного payload — минимум,
	// который обязан быть прочитан, чтобы дойти до props.plist.
	minRead := int64(512 + len(payload))
	if cr.n < minRead {
		t.Errorf("прочитано %d байт, payload не дочитан (нужно ≥ %d)", cr.n, minRead)
	}
	if cr.n > maxDecompressed {
		t.Errorf("прочитано %d байт, превышает кап %d", cr.n, maxDecompressed)
	}
}

// TestOpenPackageStopsAtProps: payload после props.plist не читается —
// парсер отдаёт метаданные сразу.
func TestOpenPackageStopsAtProps(t *testing.T) {
	payload := bytes.Repeat([]byte{0xCD}, 4<<20)
	raw := buildTarPkg(t,
		tarMember{"./props.plist", []byte(mustachePropsXML)},
		tarMember{"./payload", payload},
	)
	cr := &countingReader{r: bytes.NewReader(raw)}
	if _, err := OpenPackage(cr); err != nil {
		t.Fatalf("OpenPackage: %v", err)
	}
	if cr.n >= int64(len(raw)) {
		t.Errorf("прочитано %d из %d байт: payload не пропущен", cr.n, len(raw))
	}
}

func TestOpenPackageUnsupportedCompression(t *testing.T) {
	raw := append([]byte(xzPrefix), []byte("rest of an xz stream, unparsed")...)
	if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrUnsupportedCompression) {
		t.Fatalf("ошибка %v, хочу ErrUnsupportedCompression", err)
	}
}

func TestOpenPackageBadPackage(t *testing.T) {
	// Мусор в теле пропущенного члена: tar.Next дочитывает его и
	// падает ErrUnexpectedEOF — не тихий успех.
	truncatedMember := buildTarPkg(t,
		tarMember{"./files.plist", bytes.Repeat([]byte{'y'}, 4096)},
		tarMember{"./props.plist", []byte(mustachePropsXML)},
	)[:1024]

	cases := map[string][]byte{
		"не tar вовсе":           []byte("this is definitely not an archive"),
		"обрыв заголовка":        buildTarPkg(t, tarMember{"./payload", []byte("x")})[:300],
		"усечённое тело члена":   truncatedMember,
		"мусор после zstd-магии": append([]byte(zstdMagic), []byte("garbage after magic")...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrBadPackage) {
				t.Fatalf("ошибка %v, хочу ErrBadPackage", err)
			}
		})
	}
}

func TestOpenPackageNoProps(t *testing.T) {
	cases := map[string][]byte{
		"только files.plist": buildTarPkg(t, tarMember{"./files.plist", []byte("<plist><dict></dict></plist>")}),
		"пустой поток":       {},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrPropsMissing) {
				t.Fatalf("ошибка %v, хочу ErrPropsMissing", err)
			}
		})
	}
}

func TestOpenPackagePropsTooLarge(t *testing.T) {
	// Размер взят из заголовка (тело не материализуем): контракт — кап
	// на декларированный размер props.plist.
	raw := tarHeaderRaw("./props.plist", maxPropsSize+1)
	if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrBadPlist) {
		t.Fatalf("ошибка %v, хочу ErrBadPlist", err)
	}
}

func TestOpenPackageNil(t *testing.T) {
	if _, err := OpenPackage(nil); !errors.Is(err, ErrBadPackage) {
		t.Fatalf("nil-источник: ошибка %v, хочу ErrBadPackage", err)
	}
}

// zeroReader отдаёт нули без материализации буфера — источник бомбы.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// zstdCompressReader стримингом сжимает r в zstd-буфер (без накопления
// распакованного в памяти — уроки 77/81).
func zstdCompressReader(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	if _, err := io.Copy(zw, r); err != nil {
		t.Fatalf("zstd copy: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// TestOpenPackageDecompressBomb: распакованное тело больше 1 GiB —
// кап срабатывает на skip'е гигантского члена, чтение стримингом.
func TestOpenPackageDecompressBomb(t *testing.T) {
	// Тело члена — 1 GiB+1 MiB нулей: размер объявлен заголовком, тело
	// стримится zeroReader'ом (в памяти не материализуется).
	total := maxDecompressed + (1 << 20)
	preamble := tarHeaderRaw("./payload", total)
	zeros := io.LimitReader(zeroReader{}, total-int64(len(preamble)))
	raw := zstdCompressReader(t, io.MultiReader(bytes.NewReader(preamble), zeros))

	if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ошибка %v, хочу ErrDecompressTooLarge", err)
	}
}

// TestOpenPackageMinimalGzip: минимальный пакет (testdata, gzip+tar,
// единственный член ./props.plist без payload) — gzip-ветка на живом
// tar-контейнере, а не на синтетике в памяти.
func TestOpenPackageMinimalGzip(t *testing.T) {
	data, err := os.ReadFile("testdata/minimal-pkg.tar.gz")
	if err != nil {
		t.Fatalf("testdata: %v", err)
	}
	want := Props{
		PkgName:       "mini",
		PkgVer:        "mini-1.0_1",
		Version:       "1.0_1",
		Architecture:  "x86_64",
		ShortDesc:     "Minimal test package",
		InstalledSize: 7,
	}
	got, err := OpenPackage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("OpenPackage(минимальный пакет): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("props = %+v,\nхочу %+v", got, want)
	}
}

// mustacheRealDigest — sha256 живого пакета Void (байты с
// repo-default.voidlinux.org/current): фикстура закреплена, чтобы
// подмена testdata не прошла молча.
const mustacheRealDigest = "feb1fdb3345eea4acc508f02dcf9d649673e97cee62c085e938f684226370879"

// mustacheRealProps — поля props.plist реального
// Mustache-4.1_1.x86_64.xbps: массивов run_depends/provides у пакета нет
// (nil), maintainer с энтити `&lt;` — xml-декодер раскодирует сам.
var mustacheRealProps = Props{
	PkgName:         "Mustache",
	PkgVer:          "Mustache-4.1_1",
	Version:         "4.1_1",
	Architecture:    "x86_64",
	ShortDesc:       "Mustache text templates for modern C++",
	Homepage:        "https://github.com/kainjow/Mustache",
	License:         "BSL-1.0",
	Maintainer:      "John <johnz@posteo.net>",
	InstalledSize:   41173,
	SourceRevisions: "Mustache:d29642fc07",
}

// TestOpenPackageRealMustache — контракт на живом пакете Void.
func TestOpenPackageRealMustache(t *testing.T) {
	data, err := os.ReadFile("testdata/Mustache-4.1_1.x86_64.xbps")
	if err != nil {
		t.Fatalf("testdata: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != mustacheRealDigest {
		t.Fatalf("sha256 фикстуры %s, хочу %s", got, mustacheRealDigest)
	}
	got, err := OpenPackage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("OpenPackage(живой Mustache): %v", err)
	}
	if !reflect.DeepEqual(got, mustacheRealProps) {
		t.Errorf("props = %+v,\nхочу %+v", got, mustacheRealProps)
	}
}
