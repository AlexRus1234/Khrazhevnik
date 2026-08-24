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

// Парсер nix narinfo — метаданных одного store path в binary cache.
// Формат: текстовые строки «key: value» (с пробелом после двоеточия),
// одна запись на файл (один narinfo = один store path). Нас интересует
// поле URL: путь к nar-архиву относительно корня кеша
// (nar/<32hex>.nar.xz). narinfo содержит Sig: <key>:… — НЕ переписываем,
// отдаём побайтово; парсер нужен только для Enumerate-задела «зеркало
// по использованию» (сессия 16 не требует): WantNar достаёт nar-путь
// из narinfo для будущего префетча. Интеграции с зеркалом нет.
//
// Защита от adversarial-ввода (фаззинг FuzzParseNarinfo): потолок
// размера 16KiB (narinfo маленький — единицы КБ; запас кратный),
// tolerant к неизвестным ключам (forward-compat), без паники на битом
// тексте. Валидатор путей: 32-hex хеш store path ([0-9a-f]{32}) — так
// зафиксировано в задаче (сессия 13); пути в URL:-поле валидны
// относительно /nar/ (nar/<32hex>.nar[.xz]) или запись отбрасывается
// (WantNar возвращает пустую строку).

package nix

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxNarinfoSize — потолок размера narinfo (фаззинг-инвариант: размер
// записи < 16KiB). Реальный narinfo — десятки строк, единицы КБ; запас
// кратный. Превышение → ErrNarinfoTooLarge, парсер не читает дальше.
const maxNarinfoSize = 16 << 10 // 16 KiB

// Ошибки парсера — типизированные, сравнение через errors.Is.
var (
	ErrNarinfoTooLarge = errors.New("nix: narinfo превышает лимит 16KiB")
	ErrBadNarinfo      = errors.New("nix: некорректный narinfo")
)

// Narinfo — разобранный narinfo одного store path. Парсер извлекает
// только поля, нужные Enumerate/WantNar и будущим нуждам; прочие ключи
// игнорируются (forward-compat). Первое значение поля выигрывает
// (дубликаты, кроме References, игнорируются).
type Narinfo struct {
	StorePath   string
	URL         string
	Compression string
	FileHash    string
	FileSize    int64
	NarHash     string
	NarSize     int64
	References  []string
	Deriver     string
	Sig         string
	System      string
}

// ParseNarinfo разбирает один narinfo из r. Tolerant: неизвестные ключи
// игнорируются, CRLF-окончания и строки без «:» — пропускаются (не
// паникует). Потолок 16KiB — превышение → ErrNarinfoTooLarge. Ошибка
// чтения r → ErrBadNarinfo-обёртка.
func ParseNarinfo(r io.Reader) (*Narinfo, error) {
	// LimitReader(+1): если прочитали больше лимита — вход превышает
	// потолок. +1 байт отличает «ровно лимит» от «больше лимита».
	data, err := io.ReadAll(io.LimitReader(r, maxNarinfoSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: чтение: %w", ErrBadNarinfo, err)
	}
	if len(data) > maxNarinfoSize {
		return nil, ErrNarinfoTooLarge
	}
	return parseNarinfoBytes(data)
}

// parseNarinfoBytes — ядро парсера на байтах (вынесено для фаззинга:
// фуззер кормит сырые байты, минуя io.Reader). Строки «key: value»,
// разделитель — первая «:»; значение — всё после неё (Sig содержит
// вторую «:» — корректно сохраняется). CRLF-толерантен. Данные уже
// в памяти (LimitReader ограничил чтение), поэтому Split по «\n» — без
// bufio.Scanner и его потолка длины токена (граничный кейс: одна
// строка размером в лимит не должна ошибаться).
func parseNarinfoBytes(data []byte) (*Narinfo, error) {
	n := &Narinfo{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			// строка без «:» — tolerant: игнорируем (комментарии, мусор)
			continue
		}
		applyNarinfoField(n, strings.TrimSpace(key), strings.TrimSpace(val))
	}
	return n, nil
}

// applyNarinfoField разбирает одно поле в Narinfo. Первое значение поля
// выигрывает (дубликаты игнорируются) — guard вынесен в setOnce-хелперы,
// чтобы держать cyclomatic complexity переключателя в рамках gocyclo.
// Неизвестные ключи игнорируются (forward-compat).
func applyNarinfoField(n *Narinfo, key, val string) {
	switch key {
	case "StorePath":
		setOnceStr(&n.StorePath, val)
	case "URL":
		setOnceStr(&n.URL, val)
	case "Compression":
		setOnceStr(&n.Compression, val)
	case "FileHash":
		setOnceStr(&n.FileHash, val)
	case "FileSize":
		setOnceInt(&n.FileSize, val)
	case "NarHash":
		setOnceStr(&n.NarHash, val)
	case "NarSize":
		setOnceInt(&n.NarSize, val)
	case "References":
		setOnceRefs(&n.References, val)
	case "Deriver":
		setOnceStr(&n.Deriver, val)
	case "Sig":
		setOnceStr(&n.Sig, val)
	case "System":
		setOnceStr(&n.System, val)
	}
}

// setOnceStr записывает строку, если поле ещё пусто (first-wins).
func setOnceStr(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

// setOnceInt парсит и записывает целое, если поле ещё 0 (first-wins).
// Битое значение → 0 (tolerant: мусор в числовом поле не валит парсер).
func setOnceInt(p *int64, v string) {
	if *p == 0 {
		*p = parseInt64(v)
	}
}

// setOnceRefs дробит References по пробелам при первой встрече (first-wins).
func setOnceRefs(p *[]string, v string) {
	if *p == nil {
		*p = splitFields(v)
	}
}

// parseInt64 — tolerant парсинг целого: битое значение → 0.
func parseInt64(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// splitFields дробит значение References по пробелам (непустые токены).
func splitFields(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		out = append(out, f)
	}
	return out
}

// isHash32 проверяет, что s — ровно 32 hex-символа ([0-9a-f]{32}):
// хеш store path в путях narinfo/nar. Задача сессии 13 — 32 hex; реальный
// nix использует своё base32-подобное кодирование, но для валидатора
// достаточно hex-контракта (синтетические тестовые данные — hex).
func isHash32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// validNarName проверяет, что имя файла в URL: — nar/<32hex>.nar[.xz]
// (без префикса nar/, только имя). Суффикс .nar.xz (сжатый, основной)
// или .nar (несжатый, редко). Хеш — 32 hex.
func validNarName(name string) bool {
	var hash string
	switch {
	case strings.HasSuffix(name, ".nar.xz"):
		hash = strings.TrimSuffix(name, ".nar.xz")
	case strings.HasSuffix(name, ".nar"):
		hash = strings.TrimSuffix(name, ".nar")
	default:
		return false
	}
	return isHash32(hash)
}

// WantNar достаёт upstream-путь nar-архива из narinfo (поле URL:).
// Возвращает путь с ведущим «/» (конвенция Enumerate/StorageKey, как в
// apt/rpmmmd/pacman/apk) — «/nar/<32hex>.nar.xz» или «/nar/<32hex>.nar».
// Запись отбрасывается (пустая строка), если URL отсутствует или невалиден
// относительно /nar/ (не nar/<32hex>.nar[.xz]): фаззинг-инвариант — все
// пути в URL:-поле валидны или запись отброшена. Задел для будущего
// префетча «зеркало по использованию»; интеграции с зеркалом нет.
func WantNar(n *Narinfo) string {
	if n == nil || n.URL == "" {
		return ""
	}
	p := strings.TrimPrefix(n.URL, "/")
	rest, ok := strings.CutPrefix(p, "nar/")
	if !ok {
		return ""
	}
	if !validNarName(rest) {
		return ""
	}
	return "/nar/" + rest
}
