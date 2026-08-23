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

// Streaming XML-парсер primary.xml (rpm-md): отдаёт location-href
// каждого <package>. Потоковый (encoding/xml Decoder.Token): не грузит
// файл целиком, без I/O — принимает io.Reader. Переиспользуется зеркалом
// (сессия 11) для обхода объектов sync'а.
//
// Защита от adversarial-ввода (фаззинг): потолки числа package-элементов
// и длины текста — парсер не паникует и не зацикливается на битом XML.
// Внешние сущности (XXE) игнорируются encoding/xml (см. parse.go).

package rpmmmd

import (
	"encoding/xml"
	"errors"
	"io"
)

// Потолки по умолчанию для защиты от adversarial-ввода (фаззинг).
// Реальный primary.xml Fedora — сотни тысяч package-элементов; запас
// кратный. Тесты гоняют границу через parsePrimary с уменьшенным lim.
const (
	maxPackages = 1 << 20 // 1 млн package-элементов
	maxPrimText = 1 << 20 // 1 МБ на одно текстовое поле
)

// Ошибки парсера — типизированные, сравнение через errors.Is.
// ErrUnexpectedEOF (общий с repomd-парсером) — «незакрытые теги».
var (
	ErrTooManyPackages = errors.New("rpm-md: слишком много package-элементов")
)

// primaryLimits — потолки парсера primary.xml.
type primaryLimits struct {
	pkgs int
	text int
}

// ParsePrimary стримит location-href каждого <package> из primary.xml.
// Ошибка прерывает обход и отдаётся последним yield'ом (путь пустой).
// Чистый EOF без package — пустой результат (не ошибка). href — путь
// относительно корня репозитория (валидируется isRelativePath).
func ParsePrimary(r io.Reader) func(yield func(string, error) bool) {
	return parsePrimary(r, primaryLimits{pkgs: maxPackages, text: maxPrimText})
}

// parsePrimary — ядро с явными потолками; ParsePrimary подставляет дефолты.
//
//nolint:gocyclo // XML-парсер: разбор package/location и depth-учёт — одна атомарная операция
func parsePrimary(r io.Reader, lim primaryLimits) func(yield func(string, error) bool) {
	return func(yield func(string, error) bool) {
		dec := xml.NewDecoder(r)
		count := 0
		depth := 0
		for {
			tok, err := dec.Token()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					_ = yield("", mapDecodeErr(err))
				}
				return
			}
			switch t := tok.(type) {
			case xml.StartElement:
				depth++
				if t.Name.Local == "package" && depth >= 1 {
					if count >= lim.pkgs {
						_ = yield("", ErrTooManyPackages)
						return
					}
					count++
					href, perr := readPackageLocation(dec)
					if perr != nil {
						_ = yield("", perr)
						return
					}
					if href != "" && !isRelativePath(href) {
						_ = yield("", ErrBadLocation)
						return
					}
					if !yield(href, nil) {
						return
					}
					// readPackageLocation уже поглотил </package>;
					// глубину восстанавливаем (выход из package).
					depth--
				} else if t.Name.Local == "location" && depth >= 2 {
					// location вне package (RepomdExtensions и т.п.) —
					// пропускаем, не интересует.
					if err := skipElement(dec); err != nil {
						_ = yield("", err)
						return
					}
					depth--
				}
			case xml.EndElement:
				depth--
			}
		}
	}
}

// readPackageLocation читает содержимое одного <package>…</package> и
// возвращает href его <location>. <location> может быть в любом месте
// внутри package (createrepo_c ставит первым, но формат не гарантирует);
// неизвестные дочерние элементы пропускаются. Глубина учитывает только
// package (1) и его дочерние (2) — вложенность глубже пропускается
// skipElement'ом.
func readPackageLocation(dec *xml.Decoder) (string, error) {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", ErrUnexpectedEOF
			}
			return "", mapDecodeErr(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "location" {
				href := attrValue(t, "href")
				if err := skipElement(dec); err != nil {
					return "", err
				}
				// нашли location — дочитывать остаток package не нужно
				// для enumerate (только href интересен), но синтаксис
				// требует дойти до </package>; skipRemainingPackage добирает.
				if err := skipRemainingPackage(dec); err != nil {
					return "", err
				}
				return href, nil
			}
			if err := skipElement(dec); err != nil {
				return "", err
			}
		case xml.EndElement:
			// </package> без <location> — пустая запись, href=""
			depth--
		}
	}
	return "", nil
}

// skipRemainingPackage дочитывает токены до балансировки </package>.
// Вызывается после того, как <location> уже извлечён; глубина = 1
// (мы внутри package, location skipElement сбалансировал свой тег).
func skipRemainingPackage(dec *xml.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ErrUnexpectedEOF
			}
			return mapDecodeErr(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			_ = t
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}
