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

// Streaming XML-парсер repomd.xml — корневого индекса rpm-md-репозитория
// (createrepo_c). Отдаёт список data-элементов: type, checksum/open-checksum,
// size/open-size, location-href, timestamp. Потоковый (encoding/xml
// Decoder.Token): не грузит файл целиком, без I/O — принимает io.Reader.
// Переиспользуется зеркалом (сессия 11) для обхода объектов sync'а и
// валидацией чексумм.
//
// Защита от adversarial-ввода (фаззинг): потолки числа data-элементов и
// длины текста — парсер не паникует и не зацикливается на битом XML.
// Внешние сущности (XXE) игнорируются: encoding/xml не раскрывает
// CUSTOM-сущности (только предопределённые &lt; &amp; …), DTD
// пропускается без подстановок — раскрывать их намеренно не нужно.

package rpmmmd

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Потолки по умолчанию для защиты от adversarial-ввода (фаззинг).
// Реальный repomd Fedora — десяток data-элементов, поля — сотни байт;
// запас кратный. Тесты гоняют границу числа записей через parseRepomd
// с уменьшенным parseLimits (1 млн реальных записей — секунды).
const (
	maxDataElements = 1 << 14 // 16 тыс data-элементов
	maxTextLen      = 1 << 20 // 1 МБ на одно текстовое поле
)

// Ошибки парсера — типизированные, сравнение через errors.Is.
var (
	ErrTooManyData   = errors.New("rpm-md: слишком много data-элементов")
	ErrTextTooLong   = errors.New("rpm-md: текст превышает лимит")
	ErrBadLocation   = errors.New("rpm-md: location-href не относительный путь")
	ErrUnexpectedEOF = errors.New("rpm-md: незакрытые теги")
)

// DataElement — одна запись <data type="…"> из repomd.xml. Поля
// соответствуют дочерним элементам createrepo_c; неизвестные элементы
// игнорируются (forward-compat).
type DataElement struct {
	Type         string
	Checksum     string // checksum (сжатого объекта)
	OpenChecksum string // open-checksum (несжатого содержимого)
	Size         int64  // size (сжатого)
	OpenSize     int64  // open-size
	LocationHref string // путь относительно корня репозитория
	Timestamp    int64
}

// parseLimits — потолки парсера. Вынесены в структуру, чтобы тесты
// прогоняли границу числа записей/длины текста на маленьких значениях
// (паттерн как в apt.Stanzas → stanzas(r, lim)).
type parseLimits struct {
	data int
	text int
}

// ParseRepomd стримит data-элементы из repomd.xml через итератор.
// Ошибка прерывает обход и отдаётся последним yield'ом (запись нулевая).
// Чистый EOF без открытых data — тихое завершение; незакрытые теги —
// ErrUnexpectedEOF. Файл без <data> — пустой результат (не ошибка):
// парсер только извлекает данные, структурную валидацию делает上层.
func ParseRepomd(r io.Reader) func(yield func(DataElement, error) bool) {
	return parseRepomd(r, parseLimits{data: maxDataElements, text: maxTextLen})
}

// parseRepomd — ядро с явными потолками; ParseRepomd подставляет дефолты.
func parseRepomd(r io.Reader, lim parseLimits) func(yield func(DataElement, error) bool) {
	return func(yield func(DataElement, error) bool) {
		dec := xml.NewDecoder(r)
		count := 0
		for {
			tok, err := dec.Token()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					_ = yield(DataElement{}, mapDecodeErr(err))
				}
				return
			}
			start, ok := tok.(xml.StartElement)
			if !ok || start.Name.Local != "data" {
				continue
			}
			if count >= lim.data {
				_ = yield(DataElement{}, ErrTooManyData)
				return
			}
			count++
			el, derr := readDataElement(dec, start, lim)
			if derr != nil {
				_ = yield(DataElement{}, derr)
				return
			}
			if !yield(el, nil) {
				return
			}
		}
	}
}

// readDataElement читает содержимое одного <data>…</data>: атрибут type
// и дочерние элементы. <location href="…"/> — пустой элемент с атрибутом,
// обрабатывается отдельно от текстовых полей (checksum, size, …).
func readDataElement(dec *xml.Decoder, start xml.StartElement, lim parseLimits) (DataElement, error) {
	var el DataElement
	for _, attr := range start.Attr {
		if attr.Name.Local == "type" {
			el.Type = attr.Value
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return DataElement{}, ErrUnexpectedEOF
			}
			return DataElement{}, mapDecodeErr(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "location" {
				el.LocationHref = attrValue(t, "href")
				if err := skipElement(dec); err != nil {
					return DataElement{}, err
				}
				continue
			}
			text, terr := readText(dec, lim.text)
			if terr != nil {
				return DataElement{}, terr
			}
			setDataField(&el, t.Name.Local, text)
		case xml.EndElement:
			// </data> — запись целиком прочитана: валидируем href.
			if el.LocationHref != "" && !isRelativePath(el.LocationHref) {
				return DataElement{}, fmt.Errorf("%w: %q", ErrBadLocation, el.LocationHref)
			}
			return el, nil
		}
	}
}

// readText собирает текстовое содержимое элемента до его закрывающего
// тега. Вложенные теги (mixed content — редкость для repomd, но фаззинг
// гоняет) пропускаются, в текст не подмешиваются. Ограничена суммарной
// длиной — защита от раздувания.
func readText(dec *xml.Decoder, maxLen int) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", ErrUnexpectedEOF
			}
			return "", mapDecodeErr(err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if b.Len()+len(t) > maxLen {
				return "", ErrTextTooLong
			}
			b.Write(t)
		case xml.StartElement:
			_ = t
			if err := skipElement(dec); err != nil {
				return "", err
			}
		case xml.EndElement:
			return strings.TrimSpace(b.String()), nil
		}
	}
}

// skipElement пропускает содержимое элемента до его закрывающего тега.
// depth уже учёл StartElement (вызывающий получил его из Token()),
// поэтому стартует с 1.
func skipElement(dec *xml.Decoder) error {
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

// mapDecodeErr оборачивает ошибку xml.Decoder: SyntaxError с «unexpected
// EOF» (усечённый поток / незакрытые теги) → ErrUnexpectedEOF; прочие
// syntax errors (включая «invalid character entity» — XXE-попытку) —
// наружу как есть. Цель: тесты и上层 различают «обрезали ввод» от
// «чужой мусор», а XXE остаётся отклонённой, не тихо проглоченной.
func mapDecodeErr(err error) error {
	if err == nil {
		return nil
	}
	var se *xml.SyntaxError
	if errors.As(err, &se) && strings.Contains(se.Error(), "unexpected EOF") {
		return ErrUnexpectedEOF
	}
	return err
}

// attrValue достаёт значение атрибута по локальному имени (без
// пространства имён) из StartElement; пустая строка — нет атрибута.
func attrValue(start xml.StartElement, name string) string {
	for _, attr := range start.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

// setDataField кладёт текст дочернего элемента в нужное поле DataElement.
// Неизвестные элементы игнорируются (forward-compat: createrepo_c
// добавляет новые поля — парсер не должен ломаться).
func setDataField(el *DataElement, name, text string) {
	switch name {
	case "checksum":
		el.Checksum = text
	case "open-checksum":
		el.OpenChecksum = text
	case "size":
		el.Size = parseInt64(text)
	case "open-size":
		el.OpenSize = parseInt64(text)
	case "timestamp":
		el.Timestamp = parseInt64(text)
	}
}

// isRelativePath проверяет, что href — относительный путь: нет scheme,
// нет ведущего «/», нет «..». dnf/zypper рассчитывают на относительный
// href от корня репо; абсолютный URL или traversal — отказ.
func isRelativePath(href string) bool {
	if href == "" || strings.HasPrefix(href, "/") {
		return false
	}
	if strings.Contains(href, "://") {
		return false
	}
	for _, seg := range strings.Split(href, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// parseInt64 безопасно парсит целое; мусор → 0 (валидация размеров —
// задача上层а, парсер только извлекает данные). Отрицательные переполнения
// через умножение отсекаются проверкой n < 0.
func parseInt64(s string) int64 {
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return 0
		}
	}
	return n
}
