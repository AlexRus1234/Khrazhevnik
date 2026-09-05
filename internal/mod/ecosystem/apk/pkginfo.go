// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; even even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Мини-парсер .PKGINFO из apk-пакета (.apk). Формат тот же, что у
// pacman: «key = value» построчно, «#» — комментарии. Поля apk-флэйвора:
// pkgname/pkgver/pkgdesc/url/builddate/packager/size/arch/license/
// origin/maintainer/commit. Парсер достаёт поля, нужные генератору
// APKINDEX (gen.go). Переиспользуется генератором и фаззингом.
//
// .PKGINFO маленький, читается целиком с потолком 64KiB (защита от
// adversarial-ввода). Tolerant: неизвестные ключи игнорируются, CRLF и
// строки без «=» пропускаются, не паникуя. Битые числа → 0.

package apk

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// maxPkgInfoSize — потолок .PKGINFO (фаззинг-инвариант: < 64KiB).
const maxPkgInfoSize = 64 << 10

// ErrPkgInfoTooLarge — .PKGINFO превышает 64KiB.
var ErrPkgInfoTooLarge = errors.New("apk: .PKGINFO превышает лимит 64KiB")

// ErrBadApk — битый .apk: не tar или нет .PKGINFO.
var ErrBadApk = errors.New("apk: некорректный .apk")

// PkgInfo — разобранный .PKGINFO. Поля, нужные APKINDEX-генератору;
// неизвестные ключи игнорируются (forward-compat). Первое значение
// выигрывает (дубли игнорируются), кроме многозначных License/Depends/
// Provides/InstallIf — собираем все вхождения (depend/provides/
// install_if идут строками «key = value», по одной зависимости).
type PkgInfo struct {
	Name       string
	Version    string
	Desc       string
	URL        string
	Arch       string
	Maintainer string
	Origin     string
	BuildDate  int64
	Size       int64
	License    []string
	Depends    []string
	Provides   []string
	InstallIf  []string
}

// ParsePkgInfo разбирает .PKGINFO из r. Tolerant к CRLF/мусору; потолок
// 64KiB — превышение → ErrPkgInfoTooLarge.
func ParsePkgInfo(r io.Reader) (*PkgInfo, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxPkgInfoSize+1))
	if err != nil {
		return nil, fmt.Errorf("apk: чтение .PKGINFO: %w", err)
	}
	if len(data) > maxPkgInfoSize {
		return nil, ErrPkgInfoTooLarge
	}
	return parsePkgInfoBytes(data)
}

// parsePkgInfoBytes — ядро на байтах (для фаззинга).
func parsePkgInfoBytes(data []byte) (*PkgInfo, error) {
	pi := &PkgInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		applyPkgInfoField(pi, key, val)
	}
	return pi, nil
}

// applyPkgInfoField разбирает одно поле. Первое значение выигрывает,
// кроме многозначных License/Depends/Provides/InstallIf. Неизвестные —
// игнор (forward-compat).
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
	case "maintainer":
		setOnceStr(&pi.Maintainer, val)
	case "origin":
		setOnceStr(&pi.Origin, val)
	case "builddate":
		setOnceInt(&pi.BuildDate, val)
	case "size":
		setOnceInt(&pi.Size, val)
	case "license", "depend", "provides", "install_if":
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
	case "install_if":
		pi.InstallIf = append(pi.InstallIf, val)
	}
}

func setOnceStr(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func setOnceInt(p *int64, v string) {
	if *p == 0 {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return
		}
		*p = n
	}
}

// readPkgInfoFromPackage читает .PKGINFO из .apk одним проходом:
// ограниченная декомпрессия (decompressApk) → tar → первый член
// .PKGINFO → ParsePkgInfo. r — сырые байты .apk (генератор tee'ит через
// sha1, поэтому читает ровно столько, сколько нужно для .PKGINFO, а
// остаток дочитывает вызывающий для хеша — как apt/pacman/rpm генераторы).
func readPkgInfoFromPackage(ctx context.Context, r io.Reader) (*PkgInfo, error) {
	br := bufio.NewReader(r)
	dr, err := decompressApk(br)
	if err != nil {
		return nil, err
	}
	defer dr.Close()
	return readPkgInfoFromTar(ctx, dr)
}

// decompressApk распознаёт формат по сигнатуре: gzip (1f 8b) или zstd
// (28 b5 2f fd); иначе — несжатый tar (редкость, но поддержим). Любая
// ветка ограничена maxDecompressedApk (1 GiB) — тем же декомпресс-
// инвариантом, что и ParseAPKINDEX (parse.go: zip-bomb guard). Раньше
// кап стоял только в Enumerate, а reindex-генератор (appendIndexEntry)
// decompress'ил без лимита: publish.max_object_size меряет СЖАТЫЕ
// байты, поэтому crafted .apk (килобайты на диске, гигабайты tar-мусора
// до .PKGINFO) рвал reindex-задачу памятью. Сентинел — ErrDecompressTooLarge
// напрямую: errors.Is работает через любые %w-обёртки tar-уровня без
// ручной трансляции. Вызывающий обязан Close (zstd-декодер держит
// worker-горутины до Close).
func decompressApk(br *bufio.Reader) (io.ReadCloser, error) {
	peek, err := br.Peek(4)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: peek: %w", ErrBadApk, err)
	}
	limit := func(rc io.ReadCloser) io.ReadCloser {
		return &limitedReadCloser{
			limitedReader: &limitedReader{r: rc, limit: maxDecompressedApk, sentinel: ErrDecompressTooLarge},
			closer:        rc,
		}
	}
	switch {
	case len(peek) >= 2 && peek[0] == 0x1f && peek[1] == 0x8b:
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return nil, fmt.Errorf("%w: gzip: %w", ErrBadApk, gzErr)
		}
		return limit(gz), nil
	case len(peek) >= 4 && peek[0] == 0x28 && peek[1] == 0xb5 && peek[2] == 0x2f && peek[3] == 0xfd:
		zr, gzErr := zstd.NewReader(br)
		if gzErr != nil {
			return nil, fmt.Errorf("%w: zstd: %w", ErrBadApk, gzErr)
		}
		return limit(zstdReadCloser{zr}), nil
	}
	return io.NopCloser(&limitedReader{r: br, limit: maxDecompressedApk, sentinel: ErrDecompressTooLarge}), nil
}

// limitedReadCloser — limitedReader с Close исходного ридера: лимит
// считается на Read, Close пробрасывается (см. decompressApk про
// zstd-горутины).
type limitedReadCloser struct {
	*limitedReader
	closer io.Closer
}

func (l *limitedReadCloser) Close() error { return l.closer.Close() }

// zstdReadCloser адаптирует *zstd.Decoder к io.ReadCloser: Close у
// декодера безвозвратный и без error, контракт io.Closer требует error.
type zstdReadCloser struct{ *zstd.Decoder }

func (z zstdReadCloser) Close() error { z.Decoder.Close(); return nil }

// readPkgInfoFromTar ищет .PKGINFO в tar-потоке и парсит его. Вынесено
// для тестирования без декомпрессии (фаззинг гоняет tar-уровень). ctx.Err()
// проверяется на каждом члене: отмена reindex-задачи раньше работала
// только между пакетами, а декомпрессия внутри пакета крутилась до
// конца потока (внешнее ревью, раунд 5).
func readPkgInfoFromTar(ctx context.Context, r io.Reader) (*PkgInfo, error) {
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("apk.pkg: отмена reindex: %w", err)
		}
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%w: .PKGINFO не найден", ErrBadApk)
			}
			return nil, fmt.Errorf("%w: чтение tar: %w", ErrBadApk, err)
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
