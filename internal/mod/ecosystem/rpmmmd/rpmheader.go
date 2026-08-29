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

// Мини-парсер RPM-заголовков: lead → signature header (skip) → main
// header → теги (name/version/release/epoch/arch/summary/…/size/buildtime).
// Нужен генератору primary.xml (gen.go): без чтения заголовка dnf/zypper
// не получат метаданные пакета. Payload (cpio) НЕ читаем — экономим байты
// и время; SHA256 всего .rpm считаем по сырому потоку через TeeReader в
// вызывающем (как apt.gen у .deb).
//
// Формат RPM: 96-байтный lead (magic 0xEDABEEODB + имя + os), затем
// signature-header (header struct: magic 0x8EADE8 + ver + reserved +
// nindex + dataLen + index entries + data store), добитый до 8-байтной
// границы, затем main-header (тот же struct) с тегами пакета. Подробно —
// rpm.org RPM Format v3. Защита от adversarial-ввода (фаззинг): потолки
// nindex (64K) и dataLen (16MiB) — на превышение ErrInvalidRPM без
// чтения гигабайтов; обрезанный поток → io.ReadFull ErrUnexpectedEOF →
// ErrInvalidRPM; чужой magic → ErrInvalidRPM. Парсер не паникует.

package rpmmmd

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// RPM-теги (подмножество, нужное primary.xml). Константы — canonical
// номера тегов rpm.org; Unknown-теги игнорируются (forward-compat).
// RequireName/ProvideName — имена зависимостей (без версий-диапазонов:
// те живут в отдельных тегах RequireVersion/Flags, которые dnf
// резолвит опционально — entry с одним name клиенты принимают).
const (
	tagName         = 1000
	tagVersion      = 1001
	tagRelease      = 1002
	tagEpoch        = 1003
	tagSummary      = 1004
	tagDescription  = 1005
	tagBuildTime    = 1006
	tagSize         = 1009
	tagLicense      = 1014
	tagURL          = 1016
	tagArch         = 1022
	tagSourceRPM    = 1044
	tagProvideName  = 1047
	tagRequireName  = 1049
	tagConflictName = 1054
)

// Типы данных индексных записей. Парсер достаёт string/int32/
// string-array; int64/char/bin игнорируются (forward-compat:
// createrepo_c иногда кладёт массивы — нас интересует первое значение).
const (
	typeString      = 6
	typeInt32       = 4
	typeStringArray = 8
)

// Потолки защиты от adversarial-ввода (фаззинг). Реальный main header
// Fedora — десятки тегов, data — единицы-десятки КБ; запас кратный.
// Превышение → ErrInvalidRPM без чтения данных.
const (
	maxHeaderData   = 16 << 20 // 16 MiB на data-секцию заголовка
	maxIndexEntries = 1 << 16  // 64K индексных записей
)

// ErrInvalidRPM — битый RPM: неверный lead/header-magic, обрезанный
// поток, превышение потолков, отсутствие обязательных тегов. Сравнение
// через errors.Is (как у парсеров parse.go/primary.go).
var ErrInvalidRPM = errors.New("rpm-md: некорректный RPM")

// RPMHeader — поля из main header, нужные primary.xml. Epoch 0 = нет
// эпохи (в primary.xml выводится epoch="0", как createrepo_c). Size —
// установленный размер (RPMTAG_SIZE), не размер файла: размер файла
// берётся из Storage.Meta (package-атрибут <size>). Requires/Provides —
// имена зависимостей (rpm:requires/rpm:provides, entry без
// flags/ver/rel); SourceRPM — имя исходного SRPM (rpm:sourcerpm).
type RPMHeader struct {
	Name        string
	Version     string
	Release     string
	Epoch       int64
	Arch        string
	Summary     string
	Description string
	License     string
	URL         string
	Size        int64
	BuildTime   int64
	SourceRPM   string
	Requires    []string
	Provides    []string
}

// leadMagic — 4 байта 0xED 0xAB 0xEE 0xDB в начале .rpm.
var leadMagic = [...]byte{0xed, 0xab, 0xee, 0xdb}

// Размеры структур формата RPM (байты).
const (
	leadSize           = 96
	headerPreambleSize = 16 // magic(3)+ver(1)+reserved(4)+nindex(4)+datalen(4)
	indexEntrySize     = 16 // tag(4)+type(4)+offset(4)+count(4)
	sigHeaderAlign     = 8  // main header выравнен на 8 от начала sig header
)

// ParseRPMHeader парсит .rpm из r: lead → sig header (skip) → main
// header → теги. Читает только заголовочную часть — пейлоад не трогает,
// поэтому безопасен для больших пакетов и стримится поверх TeeReader
// (контент-SHA256 считает вызывающий, дочитывая остаток потока). Битый
// или чужой формат → ErrInvalidRPM.
//
//nolint:gocyclo // lead → sig → main — линейная последовательность чтения
func ParseRPMHeader(r io.Reader) (*RPMHeader, error) {
	br := bufio.NewReader(r)

	lead := make([]byte, leadSize)
	if _, err := io.ReadFull(br, lead); err != nil {
		return nil, fmt.Errorf("%w: lead: %w", ErrInvalidRPM, err)
	}
	if lead[0] != leadMagic[0] || lead[1] != leadMagic[1] ||
		lead[2] != leadMagic[2] || lead[3] != leadMagic[3] {
		return nil, fmt.Errorf("%w: неверный lead-magic", ErrInvalidRPM)
	}

	// Signature header: пропускаем целиком (нам не нужны подписи
	// пакета — primary.xml их не несёт). Читаем preamble, затем
	// index+data добиваем до 8-байтной границы от начала sig header.
	sigN, sigDataLen, err := readHeaderPreamble(br)
	if err != nil {
		return nil, fmt.Errorf("%w: sig header preamble: %w", ErrInvalidRPM, err)
	}
	if sigN > maxIndexEntries || sigDataLen > maxHeaderData {
		return nil, fmt.Errorf("%w: sig header слишком велик (nindex=%d dataLen=%d)", ErrInvalidRPM, sigN, sigDataLen)
	}
	sigPayload := int64(sigN)*indexEntrySize + int64(sigDataLen)
	if err := drain(br, sigPayload); err != nil {
		return nil, fmt.Errorf("%w: sig header payload: %w", ErrInvalidRPM, err)
	}
	// lead (96) и preamble (16) кратны 8, поэтому выравнивание
	// считается от (index+data): добить sigPayload до кратного 8.
	pad := (sigHeaderAlign - (sigPayload % sigHeaderAlign)) % sigHeaderAlign
	if err := drain(br, pad); err != nil {
		return nil, fmt.Errorf("%w: sig header padding: %w", ErrInvalidRPM, err)
	}

	// Main header: preamble + index + data (data читаем целиком, чтобы
	// доставать строковые теги по offset).
	n, dataLen, err := readHeaderPreamble(br)
	if err != nil {
		return nil, fmt.Errorf("%w: main header preamble: %w", ErrInvalidRPM, err)
	}
	if n > maxIndexEntries || dataLen > maxHeaderData {
		return nil, fmt.Errorf("%w: main header слишком велик (nindex=%d dataLen=%d)", ErrInvalidRPM, n, dataLen)
	}
	index := make([]byte, int(n)*indexEntrySize)
	if _, err := io.ReadFull(br, index); err != nil {
		return nil, fmt.Errorf("%w: main index: %w", ErrInvalidRPM, err)
	}
	data := make([]byte, dataLen)
	if dataLen > 0 {
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, fmt.Errorf("%w: main data: %w", ErrInvalidRPM, err)
		}
	}
	return extractHeader(index, data)
}

// readHeaderPreamble читает 16-байтную преамбулу header struct и
// возвращает (nindex, dataLen). Проверяет magic 0x8EADE8 и version 1.
func readHeaderPreamble(br *bufio.Reader) (uint32, uint32, error) {
	var p [headerPreambleSize]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return 0, 0, err
	}
	if p[0] != 0x8e || p[1] != 0xad || p[2] != 0xe8 {
		return 0, 0, errors.New("неверный header-magic")
	}
	if p[3] != 0x01 {
		return 0, 0, fmt.Errorf("неподдерживаемая версия header: %d", p[3])
	}
	nindex := binary.BigEndian.Uint32(p[8:12])
	dataLen := binary.BigEndian.Uint32(p[12:16])
	return nindex, dataLen, nil
}

// extractHeader разбирает index entries и data store в RPMHeader.
// Неизвестные теги игнорируются (forward-compat); обязательные
// name/version/release/arch — проверяются в конце (их нет → битый RPM).
//
//nolint:gocyclo // один switch на все теги — атомарная операция разбора
func extractHeader(index, data []byte) (*RPMHeader, error) {
	h := &RPMHeader{}
	for i := 0; i+indexEntrySize <= len(index); i += indexEntrySize {
		tag := binary.BigEndian.Uint32(index[i:])
		typ := binary.BigEndian.Uint32(index[i+4:])
		off := binary.BigEndian.Uint32(index[i+8:])
		count := binary.BigEndian.Uint32(index[i+12:])
		switch tag {
		case tagName:
			h.Name = readHeaderString(data, off)
		case tagVersion:
			h.Version = readHeaderString(data, off)
		case tagRelease:
			h.Release = readHeaderString(data, off)
		case tagArch:
			h.Arch = readHeaderString(data, off)
		case tagSummary:
			h.Summary = readHeaderString(data, off)
		case tagDescription:
			h.Description = readHeaderString(data, off)
		case tagLicense:
			h.License = readHeaderString(data, off)
		case tagURL:
			h.URL = readHeaderString(data, off)
		case tagSourceRPM:
			h.SourceRPM = readHeaderString(data, off)
		case tagEpoch:
			h.Epoch = readHeaderInt32(data, off, typ)
		case tagSize:
			h.Size = readHeaderInt32(data, off, typ)
		case tagBuildTime:
			h.BuildTime = readHeaderInt32(data, off, typ)
		case tagRequireName:
			h.Requires = readHeaderStringArray(data, off, count, typ)
		case tagProvideName:
			h.Provides = readHeaderStringArray(data, off, count, typ)
		}
	}
	if h.Name == "" || h.Version == "" || h.Release == "" || h.Arch == "" {
		return nil, fmt.Errorf("%w: нет обязательных тегов name/version/release/arch", ErrInvalidRPM)
	}
	return h, nil
}

// readHeaderString достаёт nul-terminated строку из data по offset.
// Выход за границу или отсутствие nul → строка до конца data (tolerant:
// битое значение не валит парсер, валидация — задача上层а).
func readHeaderString(data []byte, off uint32) string {
	if int(off) >= len(data) {
		return ""
	}
	rest := data[off:]
	for i, b := range rest {
		if b == 0 {
			return string(rest[:i])
		}
	}
	return string(rest)
}

// readHeaderInt32 достаёт int32 (big-endian) из data по offset. Для
// массивов (count>1) берёт первый элемент — createrepo_c кладёт
// одиночные значения; массивы int32 в нужных тегах не встречаются.
// Тип не-string/int32 → 0 (tolerant). Выход за границу → 0.
func readHeaderInt32(data []byte, off, typ uint32) int64 {
	if typ != typeInt32 {
		return 0
	}
	end := int(off) + 4
	if end > len(data) {
		return 0
	}
	return int64(binary.BigEndian.Uint32(data[off:end]))
}

// readHeaderStringArray достаёт count nul-terminated строк подряд из
// data по offset (STRING_ARRAY, тип 8 — так REQUIRENAME/PROVIDENAME
// хранятся в реальных .rpm). Чужой тип или выход за границу → nil
// (tolerant: битый массив не валит парсер); лишний count по сравнению
// с фактическими строками даёт собранные строки.
func readHeaderStringArray(data []byte, off, count, typ uint32) []string {
	if typ != typeStringArray || count == 0 || int(off) >= len(data) {
		return nil
	}
	rest := data[off:]
	out := make([]string, 0, count)
	for i := uint32(0); i < count && len(rest) > 0; i++ {
		s := rest
		if idx := bytes.IndexByte(rest, 0); idx >= 0 {
			s = rest[:idx]
			rest = rest[idx+1:]
		} else {
			rest = nil
		}
		out = append(out, string(s))
	}
	return out
}

// drain пропускает n байт из br. Отдельная функция — для читаемости и
// чтобы единообразно обрабатывать sig payload и padding.
func drain(br *bufio.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, br, n); err != nil {
		return err
	}
	return nil
}
