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

// Range-раздача (волна Range-206, сессии 111–112): единая точка семантики
// 200/206/416 для прокси-кеша и личных репо. Multi-диапазоны до капа
// (multipart — сессия 112), If-Range — 113.

package web

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"khrazhevnik/internal/core/port"
)

// errNoOverlap — ни один запрошенный диапазон не пересекается с телом
// (RFC 9110 §14.2: 416 с Content-Range: bytes */N). Sentinel: сравнение
// через errors.Is, парсер stdlib его не экспортирует.
var errNoOverlap = errors.New("диапазоны не пересекаются с объектом")

// byteRange — нормализованный диапазон [start, start+length). Суффиксные
// формы (bytes=-N) парсер сводит к start/length, как это делает stdlib.
type byteRange struct {
	start  int64
	length int64
}

// serveRanged отдаёт тело объекта с учётом заголовка Range.
//
// Вызывающий уже выставил ETag/Content-Type/Last-Modified/Content-Length/
// X-Cache; хелпер добавляет Accept-Ranges и, при одном диапазоне, заменяет
// Content-Length/Content-Range. openFull/openRange открывают тело
// соответственно целиком и срезом; onBytes получает реально отданные
// байты, onRange зовётся один раз на 206-ответ (метрика).
//
// Семантика ошибок: синтаксический мусор и запрос без диапазонов — 200-
// полный (сервер MAY игнорировать Range); ни одного пересечения — 416;
// ровно один диапазон — 206; от 2 до maxMultipartRanges — 206
// multipart/byteranges; больше — 200-полный.
func serveRanged(
	w http.ResponseWriter,
	r *http.Request,
	meta port.Meta,
	openFull func() (io.ReadCloser, error),
	openRange func(start, length int64) (io.ReadCloser, error),
	onBytes func(int64),
	onRange func(),
) {
	raw := r.Header.Get("Range")
	if raw == "" || meta.Size < 0 {
		// Без Range — полное тело. При неизвестном размере суффиксы и
		// 416 неразрешимы — тоже полное тело.
		sendFull(w, r, openFull, onBytes)
		return
	}

	// If-Range (RFC 9110 §13.1.5) до разбора Range: валидатор совпал —
	// диапазон применяется, иначе отдаём полное тело. Отдать срез от
	// ДРУГОЙ версии байт опаснее, чем полное тело, — клиент склеит мусор
	// и обвинит чексумму upstream.
	if !ifRangeAllows(r.Header.Get("If-Range"), meta) {
		sendFull(w, r, openFull, onBytes)
		return
	}

	ranges, err := parseByteRanges(raw, meta.Size)
	if err != nil {
		if errors.Is(err, errNoOverlap) {
			writeUnsatisfiable(w, meta.Size)
			return
		}
		sendFull(w, r, openFull, onBytes)
		return
	}
	if len(ranges) == 0 {
		// Пустой Range (например, "bytes=") — полное тело.
		sendFull(w, r, openFull, onBytes)
		return
	}
	if len(ranges) > 1 {
		if len(ranges) > maxMultipartRanges {
			// Свыше капа — честный 200-полный: 256-частный ответ на
			// мегабайты заголовков дороже повторной выдачи, а librepo
			// при 200 сам режет max_ranges пополам и сходится вниз.
			sendFull(w, r, openFull, onBytes)
			return
		}
		serveMultipart(w, r, meta, ranges, openRange, onBytes, onRange)
		return
	}

	rg := ranges[0]
	if rg.length <= 0 {
		// Суффикс -0: срез нулевой длины неотдаваем — как «нет
		// пересечения» (иначе битый Content-Range end<start).
		writeUnsatisfiable(w, meta.Size)
		return
	}

	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", formatContentRange(rg.start, rg.length, meta.Size))
	w.Header().Set("Content-Length", formatInt(rg.length))
	if r.Method == http.MethodHead {
		// Тело не открывается: io.Copy на HEAD читал бы весь объект
		// вхолостую и наращивал счётчики полным размером — так
		// счётчики честны (0 байт тела).
		w.WriteHeader(http.StatusPartialContent)
		if onRange != nil {
			onRange()
		}
		return
	}

	body, err := openRange(rg.start, rg.length)
	if err != nil {
		// Диапазон валиден, но носитель отказал: не отдаём 206 с битым
		// Content-Length — снимаем диапазонные заголовки и маппим ошибку
		// как обычно (503/404/…).
		w.Header().Del("Content-Length")
		w.Header().Del("Content-Range")
		writeProxyError(w, err)
		return
	}
	defer body.Close()
	w.WriteHeader(http.StatusPartialContent)
	n, copyErr := io.CopyBuffer(newStallWriter(w), body, make([]byte, 32*1024))
	if copyErr != nil {
		// Обрыв клиента/write-deadline: n байт реально ушли — счётчики
		// честны; лог обрыва живёт в вызывающем (здесь нет logger).
		_ = copyErr
	}
	if onBytes != nil {
		onBytes(n)
	}
	if onRange != nil {
		onRange()
	}
}

// ifRangeAllows — решение по If-Range (RFC 9110 §13.1.5), принимается до
// разбора Range. Валидатор совпал → true (диапазон применяется); не
// совпал или его у нас нет → false (полное тело). Семантика:
//   - значение в кавычках (сильный или W/-слабый тег) — точное сравнение
//     строк с meta.ETag; слабый тег клиента (W/"x") с нашим сильным ("x")
//     не совпадает, своих слабых мы не выдаём, пустой ETag — не совпадение;
//   - иначе HTTP-дата (http.ParseTime), сравнивается UTC-секунда с
//     meta.ModTime (HTTP-дата секундная — дробная часть не мешает);
//   - ни тег, ни дата / нет валидатора (ETag пуст и ModTime zero) → false.
func ifRangeAllows(ifRange string, meta port.Meta) bool {
	if ifRange == "" {
		// If-Range не задан — Range применяется безусловно.
		return true
	}
	if strings.HasPrefix(ifRange, `"`) || strings.HasPrefix(ifRange, "W/") {
		return meta.ETag != "" && ifRange == meta.ETag
	}
	t, err := http.ParseTime(ifRange)
	if err != nil {
		return false
	}
	if meta.ModTime.IsZero() {
		return false
	}
	return t.UTC().Truncate(time.Second).Equal(meta.ModTime.UTC().Truncate(time.Second))
}

// maxMultipartRanges — предел числа диапазонов в multipart/byteranges.
// 256 — стартовое max_ranges librepo (zck_get_missing_range): dnf5/zchunk
// шлёт не больше и сходится без деградации, получив 200-полный (librepo
// режет max_ranges вдвое). Свыше — не отдаём: 256-частный ответ на
// мегабайты заголовков дороже повторной выдачи тела.
const maxMultipartRanges = 256

// serveMultipart отдаёт >1 диапазона как multipart/byteranges. Тело и
// Content-Length просчитаны заранее, до WriteHeader: длины частей и
// оверхед разделителей известны, а stall-writer/write-deadline любят
// предсказуемый размер. Части строго последовательны — один открытый
// ридер в моменте (256 FD не копятся), Close — deferred в итерации.
func serveMultipart(
	w http.ResponseWriter,
	r *http.Request,
	meta port.Meta,
	ranges []byteRange,
	openRange func(start, length int64) (io.ReadCloser, error),
	onBytes func(int64),
	onRange func(),
) {
	// Граница случайна только против коллизии с телом (не секрет): 16
	// байт crypto/rand. port.Rand сюда не прокинуть без расширения Deps
	// — сознательно: на контракты это не влияет.
	var raw [16]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		// Документировано как невозможное; fail-closed к ошибке лучше
		// сломанного multipart (открытого ридера ещё нет).
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return
	}
	boundary := hex.EncodeToString(raw[:])
	contentType := w.Header().Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Точный Content-Length: сумма длин тел + константный каркас частей
	// + финальная граница. Всё известно до записи.
	total := int64(len("--" + boundary + "--\r\n"))
	for _, rg := range ranges {
		total += rg.length
		total += int64(partOverhead(boundary, contentType, formatContentRange(rg.start, rg.length, meta.Size)))
	}

	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", "multipart/byteranges; boundary="+boundary)
	w.Header().Set("Content-Length", formatInt(total))
	if r.Method == http.MethodHead {
		// Тело не открывается: счётчики честны (0 байт тела), размер
		// multipart-обёртки объявлен.
		w.WriteHeader(http.StatusPartialContent)
		if onRange != nil {
			onRange()
		}
		return
	}

	w.WriteHeader(http.StatusPartialContent)
	sw := newStallWriter(w)
	var sent int64
	final := false
	for _, rg := range ranges {
		n, err := writeMultipartPart(sw, boundary, contentType, meta.Size, rg, openRange)
		sent += n
		if err != nil {
			// Статус уже отправлен: обрыв клиента/декодера — честно
			// прекращаем и закрываем ридер (defer в helper'е), а не
			// пишем дальше в мёртвое соединение.
			break
		}
		final = true
	}
	if final {
		// Закрывающая граница; её обрыв клиента метрику байт не двигает
		// (sent — байты ТЕЛА).
		_, _ = io.WriteString(sw, "--"+boundary+"--\r\n")
	}
	if onBytes != nil {
		onBytes(sent)
	}
	if onRange != nil {
		onRange()
	}
}

// writeMultipartPart пишет одну часть и возвращает число скопированных
// байт ТЕЛА (каркас не считается: onBytes — байты объекта, как в
// однодиапазонной ветке). Ридер закрывается defer'ом до следующей части,
// так что в моменте открыт максимум один.
func writeMultipartPart(
	w io.Writer,
	boundary, contentType string,
	size int64,
	rg byteRange,
	openRange func(start, length int64) (io.ReadCloser, error),
) (int64, error) {
	body, err := openRange(rg.start, rg.length)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	head := "--" + boundary + "\r\n" +
		"Content-Range: " + formatContentRange(rg.start, rg.length, size) + "\r\n" +
		"Content-Type: " + contentType + "\r\n\r\n"
	if _, err := io.WriteString(w, head); err != nil {
		return 0, err
	}
	n, err := io.CopyBuffer(w, body, make([]byte, 32*1024))
	if err != nil {
		return n, err
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return n, err
	}
	return n, nil
}

// partOverhead — байты каркаса одной части: "--B\r\n", два заголовка,
// пустая строка и CRLF после данных. Длина тела сюда не входит.
func partOverhead(boundary, contentType, contentRange string) int {
	return len("--"+boundary+"\r\n") +
		len("Content-Range: "+contentRange+"\r\n") +
		len("Content-Type: "+contentType+"\r\n") +
		len("\r\n") + len("\r\n")
}

// sendFull — ветка полного тела (200): заголовки вызывающего сохранены,
// добавляется только Accept-Ranges. На HEAD тело не открывается.
func sendFull(w http.ResponseWriter, r *http.Request, openFull func() (io.ReadCloser, error), onBytes func(int64)) {
	w.Header().Set("Accept-Ranges", "bytes")
	if r.Method == http.MethodHead {
		if onBytes != nil {
			onBytes(0)
		}
		return
	}
	body, err := openFull()
	if err != nil {
		w.Header().Del("Content-Length")
		writeProxyError(w, err)
		return
	}
	defer body.Close()
	n, _ := io.CopyBuffer(newStallWriter(w), body, make([]byte, 32*1024))
	if onBytes != nil {
		onBytes(n)
	}
}

// writeUnsatisfiable — 416 (RFC 9110): Content-Range: bytes */N, тело не
// открывается. Content-Length вызывающего снимается — иначе сервер
// объявил бы размер тела, которого нет.
func writeUnsatisfiable(w http.ResponseWriter, size int64) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Range", "bytes */"+formatInt(size))
	w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
}

// formatContentRange — "bytes <first>-<last>/<size>" для одного среза.
func formatContentRange(start, length, size int64) string {
	return "bytes " + formatInt(start) + "-" + formatInt(start+length-1) + "/" + formatInt(size)
}

// parseByteRanges — порт неэкспортируемого parseRange из net/http (stdlib
// не открывает его наружу, а семантика stdlib — контракт волны). Возврат:
// синтаксическая ошибка → мусорный Range (200-полный); errNoOverlap → ни
// одного пересечения (416); иначе — нормализованные диапазоны, включая
// суффиксные bytes=-N. Порядок сохраняется как в заголовке (RFC 9110 не
// требует сортировки; multipart-части идут в этом же порядке).
//
//nolint:gocyclo // ветвления — семантика RFC 9110 и stdlib-порта, не сложность логики
func parseByteRanges(s string, size int64) ([]byteRange, error) {
	const prefix = "bytes="
	if !strings.HasPrefix(s, prefix) {
		return nil, errors.New("invalid range")
	}
	var ranges []byteRange
	noOverlap := false
	for _, ra := range strings.Split(s[len(prefix):], ",") {
		ra = strings.TrimSpace(ra)
		if ra == "" {
			continue
		}
		start, end, ok := strings.Cut(ra, "-")
		if !ok {
			return nil, errors.New("invalid range")
		}
		start, end = strings.TrimSpace(start), strings.TrimSpace(end)
		var r byteRange
		if start == "" {
			// <suffix-length>: N байт от конца; пустой или -N — мусор.
			if end == "" || end[0] == '-' {
				return nil, errors.New("invalid range")
			}
			i, err := strconv.ParseInt(end, 10, 64)
			if i < 0 || err != nil {
				return nil, errors.New("invalid range")
			}
			if i > size {
				i = size
			}
			r.start = size - i
			r.length = size - r.start
		} else {
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			if i >= size {
				// Начало за концом объекта — диапазон не пересекается.
				noOverlap = true
				continue
			}
			r.start = i
			if end == "" {
				// open-ended: до конца объекта.
				r.length = size - r.start
			} else {
				j, err := strconv.ParseInt(end, 10, 64)
				if err != nil || r.start > j {
					return nil, errors.New("invalid range")
				}
				if j >= size {
					j = size - 1
				}
				r.length = j - r.start + 1
			}
		}
		ranges = append(ranges, r)
	}
	if noOverlap && len(ranges) == 0 {
		return nil, errNoOverlap
	}
	return ranges, nil
}
