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

// Streaming-парсер apk APKINDEX.tar.gz (gzip+tar): отдаёт записи индекса
// (поле F: — путь к .apk пакету). Потоковый (archive/tar Reader.Next):
// не грузит архив целиком, без I/O на уровне парсера — принимает io.Reader
// сжатого потока, сам разжимает gzip. Переиспользуется зеркалом
// (сессия 11) для Enumerate и фаззингом (через parseAPKINDEXTar —
// отдельная точка входа на распакованном tar-потоке).
//
// Формат APKINDEX: tar-архив с одним-единственным файлом «APKINDEX»
// (без расширения), содержимое — список записей, разделённых пустой
// строкой; каждая запись — набор строк «K:V» (C:checksum, P:pkgname,
// V:version, F:filepath, …). Нас интересует только F: (путь пакета).
//
// Защита от adversarial-ввода (фаззинг): декомпресс-лимит 1GiB —
// gzip-декомпрессия останавливается на пороге, защищая от zip-bomb.
// Дополнительно: потолки числа записей и размера одного APKINDEX-файла
// в архиве — парсер не паникует и не зацикливается на битом tar / битом
// текстовом формате.

package apk

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
)

// Потолки по умолчанию для защиты от adversarial-ввода (фаззинг).
// Реальный APKINDEX Alpine main/x86_64 — десятки тысяч пакетов, файл
// в tar-архиве — единицы мегабайт; запас кратный. Декомпресс-лимит 1GiB —
// инвариант сессии 12 (zip-bomb guard, общий с pacman).
const (
	maxDecompressedApk = int64(1 << 30) // 1 GiB — лимит на разжатый gzip-поток
	maxIndexEntries    = 1 << 20        // 1 млн записей в APKINDEX
	maxIndexFileSize   = 1 << 26        // 64 МБ на один файл APKINDEX в tar
	maxIndexLines      = 1 << 20        // 1 млн строк в одном APKINDEX
)

// Ошибки парсера — типизированные, сравнение через errors.Is.
var (
	ErrDecompressTooLarge = errors.New("apk: декомпрессия превысила лимит")
	ErrTooManyEntries     = errors.New("apk: слишком много записей в APKINDEX")
	ErrIndexTooLarge      = errors.New("apk: файл APKINDEX превышает лимит")
	ErrBadGzip            = errors.New("apk: некорректный gzip-поток")
)

// IndexEntry — одна запись из APKINDEX: поле F: (путь к .apk) и
// опционально P: (имя пакета), V: (версия) для будущих нужд. Парсер
// извлекает только то, что нужно Enumerate.
type IndexEntry struct {
	FilePath string
	Name     string
	Version  string
}

// parseLimits — потолки парсера. Вынесены в структуру, чтобы тесты
// прогоняли границу на маленьких значениях (паттерн как в pacman).
type parseLimits struct {
	decompressed int64
	entries      int
	fileSize     int
	lines        int
}

// ParseAPKINDEX стримит записи из APKINDEX.tar.gz (gzip-сжатый tar).
// Ошибка прерывает обход и отдаётся последним yield'ом (запись nil).
// Чистый EOF — тихое завершение. Декомпресс-лимит 1GiB — защита от
// zip-bomb.
func ParseAPKINDEX(r io.Reader) iter.Seq2[*IndexEntry, error] {
	return parseAPKINDEX(r, parseLimits{
		decompressed: maxDecompressedApk,
		entries:      maxIndexEntries,
		fileSize:     maxIndexFileSize,
		lines:        maxIndexLines,
	})
}

// parseAPKINDEX — ядро с явными потолками; ParseAPKINDEX подставляет
// дефолты. Сначала разжимает gzip через limitedReader (декомпресс-лимит),
// затем передаёт распакованный tar-поток в parseAPKINDEXTar.
func parseAPKINDEX(r io.Reader, lim parseLimits) iter.Seq2[*IndexEntry, error] {
	return func(yield func(*IndexEntry, error) bool) {
		gr, err := gzip.NewReader(r)
		if err != nil {
			_ = yield(nil, fmt.Errorf("%w: %w", ErrBadGzip, err))
			return
		}
		defer func() { _ = gr.Close() }()
		limited := &limitedReader{r: gr, limit: lim.decompressed, sentinel: errDecompressLimit}
		for entry, perr := range parseAPKINDEXTar(limited, lim) {
			if perr != nil {
				if errors.Is(perr, errDecompressLimit) {
					perr = ErrDecompressTooLarge
				}
				_ = yield(nil, perr)
				return
			}
			if !yield(entry, nil) {
				return
			}
		}
	}
}

// ParseAPKINDEXTar стримит записи из распакованного tar-потока.
// Экспортнутая точка входа для фаззинга: фуззер кормит сырые байты как
// tar-поток, минуя gzip-декомпрессию (инвариант — парсер tar/текста
// не паникует на произвольном вводе). Тесты zip-bomb guard проходят
// через parseAPKINDEX (с gzip и декомпресс-лимитом).
func ParseAPKINDEXTar(r io.Reader) iter.Seq2[*IndexEntry, error] {
	return parseAPKINDEXTar(r, parseLimits{
		decompressed: maxDecompressedApk,
		entries:      maxIndexEntries,
		fileSize:     maxIndexFileSize,
		lines:        maxIndexLines,
	})
}

// parseAPKINDEXTar — ядро tar-парсера с явными потолками. Идёт по
// tar-записям, ищет файл с именем «APKINDEX» (без расширения), парсит
// текстовый формат «K:V» с разделителем записей — пустой строкой.
// Несколько файлов в архиве — берём первый APKINDEX (формат фиксирован,
// второй файл — расширение формата, не используется).
func parseAPKINDEXTar(r io.Reader, lim parseLimits) iter.Seq2[*IndexEntry, error] {
	return func(yield func(*IndexEntry, error) bool) {
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				if errors.Is(err, errDecompressLimit) {
					_ = yield(nil, ErrDecompressTooLarge)
					return
				}
				_ = yield(nil, fmt.Errorf("apk: чтение tar: %w", err))
				return
			}
			// только регулярный файл с именем «APKINDEX» (без расширения).
			// tar-архив apk содержит ровно один такой файл.
			if hdr.Typeflag != tar.TypeReg || !isAPKINDEXName(hdr.Name) {
				continue
			}
			// ограничиваем чтение одного файла лимитом fileSize: защита
			// от tar-записи, декларирующей гигабайты, но limitedReader
			// ниже поймает превышение при реальном чтении.
			limited := &limitedReader{r: tr, limit: int64(lim.fileSize), sentinel: errFileLimit}
			for entry, perr := range parseAPKINDEXText(limited, lim) {
				if perr != nil {
					if errors.Is(perr, errFileLimit) {
						perr = ErrIndexTooLarge
					}
					if errors.Is(perr, errDecompressLimit) {
						perr = ErrDecompressTooLarge
					}
					_ = yield(nil, perr)
					return
				}
				if !yield(entry, nil) {
					return
				}
			}
			return // один APKINDEX-файл на архив; дальше не идём
		}
	}
}

// isAPKINDEXName проверяет, что путь в tar — это файл APKINDEX.
// Alpine кладёт его без каталога (просто «APKINDEX»), но терпим к
// префиксу каталога (на случай кастомных упаковщиков).
func isAPKINDEXName(name string) bool {
	base := name
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		base = name[idx+1:]
	}
	return base == "APKINDEX"
}

// parseAPKINDEXText парсит текстовый формат APKINDEX: записи, разделённые
// пустой строкой; каждая запись — набор строк «K:V», где K — однобуквенный
// ключ, V — значение. Нас интересуют F: (filepath), P: (pkgname),
// V: (version). Остальные ключи игнорируются (forward-compat).
func parseAPKINDEXText(r io.Reader, lim parseLimits) iter.Seq2[*IndexEntry, error] {
	return func(yield func(*IndexEntry, error) bool) {
		// bufio.NewReader.ReadString('\n') корректно обрабатывает
		// (0, nil) от tar.Reader (когда тот доходит до конца файла):
		// в отличие от кастомного bufReader, не зацикливается.
		br := bufio.NewReader(r)
		var entry IndexEntry
		var hasField bool
		count := 0
		lineNo := 0
		flush := func() bool {
			if !hasField {
				return true
			}
			if count >= lim.entries {
				return false
			}
			count++
			// Копируем entry: yield(&entry, nil) отдаёт указатель на
			// локальную переменную; если обнулить entry после yield,
			// все указатели в срезе вызывающего будут указывать на
			// пустую запись. Копия разрывает ссылку.
			cp := entry
			if !yield(&cp, nil) {
				return false
			}
			entry = IndexEntry{}
			hasField = false
			return true
		}
		for {
			if lineNo >= lim.lines {
				_ = yield(nil, ErrIndexTooLarge)
				return
			}
			line, readErr := br.ReadString('\n')
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
			if line != "" {
				lineNo++
				hasField = applyIndexField(&entry, line) || hasField
			} else if !flush() {
				_ = yield(nil, ErrTooManyEntries)
				return
			}
			if readErr != nil {
				yieldFinalError(yield, readErr, flush)
				return
			}
		}
	}
}

// applyIndexField разбирает строку «K:V» и записывает значение в поле
// IndexEntry. Возвращает true, если строка была полем (имеет «:»).
// Первое значение поля выигрывает (дубликаты игнорируются). Неизвестные
// ключи игнорируются (forward-compat). Строки без «:» — tolerant: ничего
// не делают, возвращают false.
func applyIndexField(entry *IndexEntry, line string) bool {
	key, val, ok := strings.Cut(line, ":")
	if !ok {
		return false
	}
	switch key {
	case "F":
		if entry.FilePath == "" {
			entry.FilePath = val
		}
	case "P":
		if entry.Name == "" {
			entry.Name = val
		}
	case "V":
		if entry.Version == "" {
			entry.Version = val
		}
	}
	return true
}

// yieldFinalError транслирует ошибку чтения в соответствующую типизированную
// ошибку и отдаёт через yield. Перед этим flush'ит накопленную запись
// (последняя запись без завершающей пустой строки). Вынесено из
// parseAPKINDEXText для снижения cyclomatic complexity.
func yieldFinalError(yield func(*IndexEntry, error) bool, readErr error, flush func() bool) {
	switch {
	case errors.Is(readErr, errFileLimit):
		_ = yield(nil, ErrIndexTooLarge)
	case errors.Is(readErr, errDecompressLimit):
		_ = yield(nil, ErrDecompressTooLarge)
	case errors.Is(readErr, io.EOF):
		if !flush() {
			_ = yield(nil, ErrTooManyEntries)
		}
	default:
		_ = yield(nil, fmt.Errorf("apk: чтение apkindex: %w", readErr))
	}
}

// errDecompressLimit — sentinel limitedReader в parseAPKINDEX: превышен
// декомпресс-лимит (zip-bomb guard). Транслируется в ErrDecompressTooLarge.
var errDecompressLimit = errors.New("decompress limit exceeded")

// errFileLimit — sentinel limitedReader в parseAPKINDEXTar для лимита
// размера одного APKINDEX-файла. Транслируется в ErrIndexTooLarge.
var errFileLimit = errors.New("file limit exceeded")

// limitedReader — обёртка, считающая байты и возвращающая sentinel
// при превышении лимита. Разные sentinel'ы для разных лимитов — чтобы
// вызывающий код различал «декомпрессия превысила» от «файл превысил».
type limitedReader struct {
	r        io.Reader
	n        int64
	limit    int64
	sentinel error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n >= l.limit {
		return 0, l.sentinel
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.limit {
		return n, l.sentinel
	}
	return n, err
}
