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

// Мини-парсер .PKGINFO из pacman-пакета (.pkg.tar.zst). Формат —
// «key = value» построчно (пробелы вокруг «=»), «#» — комментарии,
// некоторые поля повторяются (depend, license). Парсер достаёт поля,
// нужные генератору .db (gen.go): pkgname/pkgver/pkgdesc/url/license/
// arch/builddate/packager/size. Переиспользуется генератором и фаззингом.
//
// .PKGINFO маленький (единицы КБ), поэтому читается целиком с потолком
// 64KiB (защита от adversarial-ввода). Tolerant: неизвестные ключи
// игнорируются (forward-compat), CRLF-окончания и строки без «=» —
// пропускаются, не паникуя. Битые числа → 0 (как у nix.parseNarinfoBytes).

package pacman

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// maxPkgInfoSize — потолок размера .PKGINFO (фаззинг-инвариант: запись
// < 64KiB). Реальный .PKGINFO — десятки строк, единицы КБ; запас кратный.
const maxPkgInfoSize = 64 << 10

// ErrPkgInfoTooLarge — .PKGINFO превышает 64KiB.
var ErrPkgInfoTooLarge = errors.New("pacman: .PKGINFO превышает лимит 64KiB")

// PkgInfo — разобранный .PKGINFO. Поля, нужные desc-генератору; прочие
// (makedepend, optdepend, checkdepend, backup, ...) игнорируются
// (forward-compat: makepkg добавляет поля — парсер не должен ломаться).
// Первое значение поля выигрывает (дубли игнорируются), кроме
// многозначных License/Depends/Provides/Conflicts (depend/provides/
// conflict идут строками «key = value», по одной зависимости).
type PkgInfo struct {
	Name      string
	Version   string
	Desc      string
	URL       string
	Arch      string
	Packager  string
	BuildDate int64
	Size      int64
	License   []string
	Depends   []string
	Provides  []string
	Conflicts []string
}

// ParsePkgInfo разбирает .PKGINFO из r. Tolerant к CRLF и мусору;
// потолок 64KiB — превышение → ErrPkgInfoTooLarge. Ошибка чтения r
// не оборачивается (читается через io.ReadAll на LimitReader).
func ParsePkgInfo(r io.Reader) (*PkgInfo, error) {
	// LimitReader(+1): если прочитали больше лимита — вход превышает потолок.
	data, err := io.ReadAll(io.LimitReader(r, maxPkgInfoSize+1))
	if err != nil {
		return nil, fmt.Errorf("pacman: чтение .PKGINFO: %w", err)
	}
	if len(data) > maxPkgInfoSize {
		return nil, ErrPkgInfoTooLarge
	}
	return parsePkgInfoBytes(data)
}

// parsePkgInfoBytes — ядро на байтах (для фаззинга: фуззер кормит сырые
// байты, минуя io.Reader). Данные уже в памяти (LimitReader ограничил).
func parsePkgInfoBytes(data []byte) (*PkgInfo, error) {
	pi := &PkgInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		// комментарий или пустая строка — пропускаем.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			// строка без «=» — tolerant: игнорируем.
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		applyPkgInfoField(pi, key, val)
	}
	return pi, nil
}

// applyPkgInfoField разбирает одно поле в PkgInfo. Первое значение
// выигрывает (дубли игнорируются), кроме многозначных License/Depends/
// Provides/Conflicts (собираем все вхождения). Неизвестные ключи
// игнорируются (forward-compat).
func applyPkgInfoField(pi *PkgInfo, key, val string) {
	switch key {
	case "pkgname":
		setOnceStr(&pi.Name, val)
	case "pkgver":
		setOnceStr(&pi.Version, val)
	case "pkgdesc":
		setOnceStr(&pi.Desc, val)
	case "url":
		setOnceStr(&pi.URL, val)
	case "arch":
		setOnceStr(&pi.Arch, val)
	case "packager":
		setOnceStr(&pi.Packager, val)
	case "builddate":
		setOnceInt(&pi.BuildDate, val)
	case "size":
		setOnceInt(&pi.Size, val)
	case "license", "depend", "provides", "conflict":
		// многозначные поля — по одному значению на строку.
		if val != "" {
			appendMulti(pi, key, val)
		}
	}
}

// appendMulti дописывает значение в многозначное поле (первое вхождение
// переключателя уже нормализовало key).
func appendMulti(pi *PkgInfo, key, val string) {
	switch key {
	case "license":
		pi.License = append(pi.License, val)
	case "depend":
		pi.Depends = append(pi.Depends, val)
	case "provides":
		pi.Provides = append(pi.Provides, val)
	case "conflict":
		pi.Conflicts = append(pi.Conflicts, val)
	}
}

// setOnceStr записывает строку, если поле ещё пусто (first-wins).
func setOnceStr(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

// setOnceInt парсит и записывает целое, если поле ещё 0 (first-wins).
// Битое значение → 0 (tolerant).
func setOnceInt(p *int64, v string) {
	if *p == 0 {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return
		}
		*p = n
	}
}

// readPkgInfoFromPackage читает .PKGINFO из .pkg.tar.zst одним проходом:
// zstd-декомпрессия → tar → первый член .PKGINFO → ParsePkgInfo.
// r — сырые байты .pkg.tar.zst (генератор tee'ит через SHA256, поэтому
// readPkgInfoFromPackage читает ровно столько, сколько нужно для .PKGINFO,
// а остаток дочитывает вызывающий для хеша — как apt/rpm генераторы).
func readPkgInfoFromPackage(r io.Reader) (*PkgInfo, error) {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadZstd, err)
	}
	defer zr.Close()
	pi, err := readPkgInfoFromTar(zr)
	if err != nil {
		return nil, err
	}
	return pi, nil
}

// readPkgInfoFromTar ищет .PKGINFO в tar-потоке и парсит его. Вынесено
// для тестирования без zstd (фаззинг гоняет tar-уровень).
func readPkgInfoFromTar(r io.Reader) (*PkgInfo, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("pacman: .PKGINFO не найден в .pkg.tar")
			}
			return nil, fmt.Errorf("pacman: чтение tar .pkg: %w", err)
		}
		base := hdr.Name
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}
		base = strings.TrimPrefix(base, "./")
		if base != ".PKGINFO" {
			continue
		}
		return ParsePkgInfo(tr)
	}
}
