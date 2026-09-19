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
	"testing"

	"github.com/klauspost/compress/zstd"
)

// pkgSeedAr собирает raw ar для сидов без *testing.T: имена членов —
// литералы заведомо короче 16 байт, тела фиксированы, поэтому отдельный
// помощник с t.Fatalf не нужен (buildArPkg требует *testing.T).
func pkgSeedAr(members ...arMemberSpec) []byte {
	var buf bytes.Buffer
	buf.WriteString(arMagic)
	for _, m := range members {
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

// pkgSeedZstd / pkgSeedGzip сжимают raw-ар в сид. Ошибки кодеков на
// bytes.Buffer не бывают; проверять их нечем (нет *testing.F).
func pkgSeedZstd(raw []byte) []byte {
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

func pkgSeedGzip(raw []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	return buf.Bytes()
}

// propsSig — сигнатура Props по длинам строк и размерам массивов.
// Фаззер не должен ни накапливать содержимое, ни сравнивать его
// побайтово: класс ошибок/структура важнее текста (сессия 138).
type propsSig struct {
	strs [9]int
	nums [3]int
}

func sigOfProps(p Props) propsSig {
	return propsSig{
		strs: [9]int{
			len(p.PkgName), len(p.PkgVer), len(p.Version),
			len(p.Architecture), len(p.ShortDesc), len(p.Homepage),
			len(p.License), len(p.Maintainer), len(p.SourceRevisions),
		},
		nums: [3]int{int(p.InstalledSize), len(p.RunDepends), len(p.Provides)},
	}
}

// FuzzOpenPackage гоняет ar-парсер .xbps на произвольных байтах —
// вход недоверенных пользовательских upload'ов (движок publish отдаёт
// ему тело репозитория). Инварианты: не паниковать, не зацикливаться
// (таймаут теста ловит), повторный разбор тех же байт даёт ту же ошибку
// и ту же структуру Props (детерминизм). Сиды покрывают все три ветки
// компрессии (raw/zstd/gzip), обрезки на границах заголовков, мусор с
// валидной магией zstd и гигантское поле размера члена.
func FuzzOpenPackage(f *testing.F) {
	valid := pkgSeedAr(arMemberSpec{"./props.plist", []byte(mustachePropsXML)})
	// Поле размера ar — ровно 10 байт (raw[48:58]), длиннее туда не
	// влезает: «99999999999999999999» усечётся до 10 девяток — всё
	// равно adversarial-размер ~10 GiB, гоняющий ветку капа props.
	overSize := pkgSeedAr(arMemberSpec{"./props.plist", []byte(mustachePropsXML)})
	copy(overSize[len(arMagic)+48:len(arMagic)+58], []byte("99999999999999999999")) //nolint:gocritic // фиксированное поле
	payloadFirst := pkgSeedAr(
		arMemberSpec{"./files.plist", []byte("<plist><dict></dict></plist>")},
		arMemberSpec{"./props.plist", []byte(mustachePropsXML)},
	)
	xzSeed := append([]byte(xzPrefix), []byte("rest of an xz stream")...)

	seeds := [][]byte{
		nil,
		{},
		[]byte("not an ar archive at all"),
		valid,
		pkgSeedZstd(valid),
		pkgSeedGzip(valid),
		valid[:8],  // ровно магия ar
		valid[:60], // магия + начало заголовка
		valid[:68], // магия + полный заголовок, тела нет
		append([]byte(zstdMagic), []byte("garbage after magic")...),
		overSize,
		payloadFirst,
		xzSeed,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := OpenPackage(bytes.NewReader(data))
		// Повторный разбор тех же байт обязан дать идентичный результат:
		// скрытого состояния у парсера быть не должно.
		second, secondErr := OpenPackage(bytes.NewReader(data))
		if !samePkgErr(firstErr, secondErr) {
			t.Fatalf("недетерминированная ошибка: %v vs %v", firstErr, secondErr)
		}
		if sigOfProps(first) != sigOfProps(second) {
			t.Fatalf("структура Props скачет между прогонами")
		}
	})
}

// samePkgErr сравнивает ошибки двух прогонов: nil-nil, sentinel через
// errors.Is (типизированные обёртки), иначе — равенство текста (сырые
// ошибки xml/zstd/gzip каждый прогон создаются заново, но текст
// детерминирован при отсутствии скрытого состояния).
func samePkgErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if errors.Is(a, b) || errors.Is(b, a) {
		return true
	}
	return a.Error() == b.Error()
}
