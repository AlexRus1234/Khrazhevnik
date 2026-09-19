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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"reflect"
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

// arMemberSpec — член ar для сборки тестового пакета.
type arMemberSpec struct {
	name string
	body []byte
}

// buildArPkg собирает raw ar (классические 60-байтные заголовки,
// нечётное тело выравнивается `\n`).
func buildArPkg(t *testing.T, members ...arMemberSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(arMagic)
	for _, m := range members {
		if len(m.name) > 16 {
			t.Fatalf("имя члена %q длиннее 16 байт", m.name)
		}
		hdr := bytes.Repeat([]byte{' '}, arHeaderSize)
		copy(hdr[0:16], m.name)
		copy(hdr[48:58], fmt.Sprintf("%-10d", len(m.body)))
		hdr[58], hdr[59] = '`', '\n'
		buf.Write(hdr)
		buf.Write(m.body)
		if len(m.body)%2 != 0 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// compressPackage оборачивает raw ar в выбранную компрессию.
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
	raw := buildArPkg(t,
		arMemberSpec{"./props.plist", []byte(mustachePropsXML)},
		arMemberSpec{"./files.plist", []byte("<plist><dict></dict></plist>")},
		arMemberSpec{"payload/bin", []byte("MZ")},
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

// TestOpenPackagePropsNameForms: «props.plist» и «./props.plist» —
// одно имя (libarchive пишет с префиксом, GNU-стиль — без).
func TestOpenPackagePropsNameForms(t *testing.T) {
	for _, name := range []string{"props.plist", "./props.plist"} {
		t.Run(name, func(t *testing.T) {
			raw := buildArPkg(t, arMemberSpec{name, []byte(mustachePropsXML)})
			got, err := OpenPackage(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("OpenPackage: %v", err)
			}
			if !reflect.DeepEqual(got, mustacheProps) {
				t.Errorf("props = %+v,\nхочу %+v", got, mustacheProps)
			}
		})
	}
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
	raw := buildArPkg(t,
		arMemberSpec{"./files.plist", payload},
		arMemberSpec{"./props.plist", []byte(mustachePropsXML)},
	)
	cr := &countingReader{r: bytes.NewReader(raw)}
	got, err := OpenPackage(cr)
	if err != nil {
		t.Fatalf("OpenPackage: %v", err)
	}
	if !reflect.DeepEqual(got, mustacheProps) {
		t.Errorf("props = %+v,\nхочу %+v", got, mustacheProps)
	}
	// 8 (магия) + 60 (заголовок) + тело payload — минимум, который
	// обязан быть прочитан, чтобы дойти до props.plist.
	minRead := int64(len(arMagic) + arHeaderSize + len(payload))
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
	raw := buildArPkg(t,
		arMemberSpec{"./props.plist", []byte(mustachePropsXML)},
		arMemberSpec{"payload", payload},
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

func TestOpenPackageBadAr(t *testing.T) {
	badSize := buildArPkg(t, arMemberSpec{"./props.plist", []byte(mustachePropsXML)})
	copy(badSize[len(arMagic)+48:len(arMagic)+58], []byte("12x       ")) //nolint:gocritic // фиксированная длина поля

	negativeSize := buildArPkg(t, arMemberSpec{"./props.plist", []byte(mustachePropsXML)})
	copy(negativeSize[len(arMagic)+48:len(arMagic)+58], []byte("-5        ")) //nolint:gocritic // фиксированная длина поля

	cases := map[string][]byte{
		"не ar вовсе":     []byte("this is definitely not an archive"),
		"обрыв заголовка": append([]byte(arMagic), []byte("short")...),
		"битый размер":    badSize,
		"отрицательный":   negativeSize,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrBadAr) {
				t.Fatalf("ошибка %v, хочу ErrBadAr", err)
			}
		})
	}
}

func TestOpenPackageNoProps(t *testing.T) {
	raw := buildArPkg(t,
		arMemberSpec{"./files.plist", []byte("<plist><dict></dict></plist>")},
	)
	if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrPropsMissing) {
		t.Fatalf("ошибка %v, хочу ErrPropsMissing", err)
	}
}

func TestOpenPackagePropsTooLarge(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, int(maxPropsSize)+1)
	raw := buildArPkg(t, arMemberSpec{"./props.plist", body})
	if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrBadPlist) {
		t.Fatalf("ошибка %v, хочу ErrBadPlist", err)
	}
}

func TestOpenPackageNil(t *testing.T) {
	if _, err := OpenPackage(nil); !errors.Is(err, ErrBadAr) {
		t.Fatalf("nil-источник: ошибка %v, хочу ErrBadAr", err)
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
	var hdr [arHeaderSize]byte
	for i := range hdr {
		hdr[i] = ' '
	}
	copy(hdr[0:16], "./payload")
	copy(hdr[48:58], fmt.Sprintf("%-10d", maxDecompressed+(1<<20)))
	hdr[58], hdr[59] = '`', '\n'
	preamble := append([]byte(arMagic), hdr[:]...)

	total := maxDecompressed + (1 << 20)
	zeros := io.LimitReader(zeroReader{}, total-int64(len(preamble)))
	raw := zstdCompressReader(t, io.MultiReader(bytes.NewReader(preamble), zeros))

	if _, err := OpenPackage(bytes.NewReader(raw)); !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ошибка %v, хочу ErrDecompressTooLarge", err)
	}
}
