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
	"testing"

	"github.com/klauspost/compress/zstd"
)

// pkgSeedTar собирает tar-пакет для сидов без *testing.T: writeTarPkg
// поверх bytes.Buffer ошибиться не может (проверять нечем — нет *testing.F).
func pkgSeedTar(members ...tarMember) []byte {
	var buf bytes.Buffer
	_ = writeTarPkg(&buf, members)
	return buf.Bytes()
}

// pkgSeedZstd / pkgSeedGzip сжимают tar-пакет в сид. Ошибки кодеков на
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

// FuzzOpenPackage гоняет tar-парсер .xbps на произвольных байтах —
// вход недоверенных пользовательских upload'ов (движок publish отдаёт
// ему тело репозитория). Инварианты: не паниковать, не зацикливаться
// (таймаут теста ловит), повторный разбор тех же байт даёт ту же ошибку
// и ту же структуру Props (детерминизм). Сиды покрывают все три ветки
// компрессии (raw/zstd/gzip), обрезки на границах tar-блоков, мусор с
// валидной магией zstd и гигантское поле размера члена.
func FuzzOpenPackage(f *testing.F) {
	valid := pkgSeedTar(tarMember{"./props.plist", []byte(mustachePropsXML)})
	// Заголовок с декларированным размером выше капа props.plist: тело
	// не материализуем, гоняем ветку капа (tar.Next не дочитывает).
	overSize := tarHeaderRaw("./props.plist", maxPropsSize+1)
	payloadFirst := pkgSeedTar(
		tarMember{"./files.plist", []byte("<plist><dict></dict></plist>")},
		tarMember{"./props.plist", []byte(mustachePropsXML)},
	)
	xzSeed := append([]byte(xzPrefix), []byte("rest of an xz stream")...)

	seeds := [][]byte{
		nil,
		{},
		[]byte("not a tar archive at all"),
		valid,
		pkgSeedZstd(valid),
		pkgSeedGzip(valid),
		valid[:257], // обрыв в середине заголовка блока
		valid[:512], // ровно заголовок, тела нет
		valid[:520], // заголовок + 8 байт тела
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
