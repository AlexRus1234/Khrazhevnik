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

// Streaming-парсер pacman {repo}.db (tar.gz|tar.zst — авто-детект по
// magic-байтам → tar → desc): отдаёт desc-записи (поле %FILENAME% —
// имя файла пакета). Потоковый (archive/tar Reader.Next): не грузит
// архив целиком, без I/O на уровне парсера — принимает io.Reader
// сжатого потока, сам разжимает gzip/zstd. Переиспользуется зеркалом
// (сессия 11) для Enumerate и фаззингом (через parseDBTar — отдельная
// точка входа на распакованном tar-потоке).
//
// Почему авто-детект по magic, а не по расширению: имя {repo}.db
// компрессии не несёт, а upstream'ы различаются — sync-БД Arch
// публикуется как gzip, репо-add свежих релионов — zstd. Одна точка
// детекта (newDBStream) на оба случая.
//
// Защита от adversarial-ввода (фаззинг): декомпресс-лимит 1GiB —
// декомпрессия останавливается на пороге, защищая от zip-bomb
// (маленький архив, разжимающийся в гигабайты мусора). Дополнительно:
// потолки числа desc-записей и размера одной desc — парсер не паникует
// и не зацикливается на битом tar / битом desc.

package pacman

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Потолки по умолчанию для защиты от adversarial-ввода (фаззинг).
// Реальный core.db Arch — десятки тысяч пакетов, desc — килобайты;
// запас кратный. Декомпресс-лимит 1GiB — инвариант сессии 12
// (zip-bomb guard).
const (
	maxDecompressed = int64(1 << 30) // 1 GiB — лимит на разжатый zstd-поток
	maxDescEntries  = 1 << 20        // 1 млн desc-записей
	maxDescSize     = 1 << 20        // 1 МБ на одну desc
	maxDescLines    = 1 << 14        // 16 тыс строк в одной desc
)

// Ошибки парсера — типизированные, сравнение через errors.Is.
var (
	ErrDecompressTooLarge = errors.New("pacman: декомпрессия превысила лимит")
	ErrTooManyEntries     = errors.New("pacman: слишком много desc-записей")
	ErrDescTooLarge       = errors.New("pacman: desc превышает лимит")
	ErrBadZstd            = errors.New("pacman: некорректный zstd-поток")
	ErrBadGzip            = errors.New("pacman: некорректный gzip-поток")
)

// DescEntry — одна запись из pacman .db: поле %FILENAME% (имя файла
// пакента) и опционально %NAME%/%VERSION% для будущих нужд (валидация
// чексумм). Парсер извлекает только то, что нужно Enumerate.
type DescEntry struct {
	Filename string
	Name     string
	Version  string
}

// parseLimits — потолки парсера. Вынесены в структуру, чтобы тесты
// прогоняли границу числа записей/размера desc на маленьких значениях
// (паттерн как в apt.Stanzas и rpmmmd.parseRepomd).
type parseLimits struct {
	decompressed int64
	entries      int
	descSize     int
	descLines    int
}

// ParseDB стримит desc-записи из {repo}.db (gzip/zstd-сжатый tar,
// авто-детект по magic). Ошибка прерывает обход и отдаётся последним
// yield'ом (запись nil). Чистый EOF — тихое завершение. Декомпресс-лимит
// 1GiB — защита от zip-bomb (один на обе ветки компрессии).
func ParseDB(r io.Reader) iter.Seq2[*DescEntry, error] {
	return parseDB(r, parseLimits{
		decompressed: maxDecompressed,
		entries:      maxDescEntries,
		descSize:     maxDescSize,
		descLines:    maxDescLines,
	})
}

// newDBStream — точка авто-детекта компрессии {repo}.db: читает до 4
// байт головы (короткое чтение — не ошибка, поток может кончиться
// раньше), склеивает голову с исходником через io.MultiReader —
// потребитель не видит «съеденных» байт. Выбор декомпрессора по
// magic-байтам, не по расширению: gzip (1F 8B) — sync-БД Arch, zstd —
// всё прочее (мусор без gzip-magic уходит в zstd-ветку, сохраняя
// контракт битого zstd). Close-функция гасит декодер (zstd-декодер
// держит горутины; gzip.Reader.Close — симметрия ветвей).
func newDBStream(r io.Reader) (io.Reader, func(), error) {
	head := make([]byte, 4)
	n, _ := io.ReadFull(r, head)
	rest := io.MultiReader(bytes.NewReader(head[:n]), r)
	if n >= 2 && head[0] == 0x1F && head[1] == 0x8B {
		gr, err := gzip.NewReader(rest)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrBadGzip, err)
		}
		return gr, func() { _ = gr.Close() }, nil
	}
	zr, err := zstd.NewReader(rest)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBadZstd, err)
	}
	return zr.IOReadCloser(), zr.Close, nil
}

// parseDB — ядро с явными потолками; ParseDB подставляет дефолты.
// newDBStream выбирает декомпрессор по magic (gzip/zstd), limitedReader
// ставит декомпресс-лимит, затем распакованный tar-поток уходит в
// parseDBTar. errDecompressLimit от limitedReader транслируется в
// ErrDecompressTooLarge.
func parseDB(r io.Reader, lim parseLimits) iter.Seq2[*DescEntry, error] {
	return func(yield func(*DescEntry, error) bool) {
		src, closeDec, err := newDBStream(r)
		if err != nil {
			_ = yield(nil, err)
			return
		}
		defer closeDec()
		limited := &limitedReader{r: src, limit: lim.decompressed, sentinel: errDecompressLimit}
		for entry, err := range parseDBTar(limited, lim) {
			if err != nil {
				if errors.Is(err, errDecompressLimit) {
					err = ErrDecompressTooLarge
				}
				_ = yield(nil, err)
				return
			}
			if !yield(entry, nil) {
				return
			}
		}
	}
}

// ParseDBTar стримит desc-записи из распакованного tar-потока.
// Экспортнуточка входа для фаззинга: фуззер кормит сырые байты как
// tar-поток, минуя zstd-декомпрессию (инвариант — парсер tar/desc не
// паникует на произвольном вводе). Тесты zip-bomb guard проходят через
// parseDB (с zstd и декомпресс-лимитом).
func ParseDBTar(r io.Reader) iter.Seq2[*DescEntry, error] {
	return parseDBTar(r, parseLimits{
		decompressed: maxDecompressed,
		entries:      maxDescEntries,
		descSize:     maxDescSize,
		descLines:    maxDescLines,
	})
}

// parseDBTar — ядро tar-парсера с явными потолками. Идёт по tar-записям,
// выбирает файлы «*/desc» (регулярные), парсит pacman-формат и отдаёт
// DescEntry с %FILENAME%. errDecompressLimit от нижележащего limitedReader
// (из parseDB) транслируется в ErrDecompressTooLarge; прочие ошибки tar
// отдаются с обёрткой.
func parseDBTar(r io.Reader, lim parseLimits) iter.Seq2[*DescEntry, error] {
	return func(yield func(*DescEntry, error) bool) {
		tr := tar.NewReader(r)
		count := 0
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
				_ = yield(nil, fmt.Errorf("pacman: чтение tar: %w", err))
				return
			}
			// только регулярные файлы, заканчивающиеся на «/desc»;
			// каталоги, files, depends и прочее — пропускаем.
			if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, "/desc") {
				continue
			}
			if count >= lim.entries {
				_ = yield(nil, ErrTooManyEntries)
				return
			}
			count++
			entry, err := readDesc(tr, lim)
			if err != nil {
				_ = yield(nil, err)
				return
			}
			if !yield(entry, nil) {
				return
			}
		}
	}
}

// readDesc читает содержимое desc-файла из tar-потока и парсит
// pacman-формат: поля обёрнуты в %FIELD% ... value lines ... ,
// разделитель между полями — следующий %FIELD% (без пустой строки,
// в отличие от deb822). Возвращает DescEntry с %FILENAME%, %NAME%,
// %VERSION% (остальные поля игнорируются — forward-compat).
// errDescLimit — лимит на размер одной desc (защита от раздувания);
// errDecompressLimit от parseDB пробрасывается вверх как есть (чтобы
// parseDBTar транслировал в ErrDecompressTooLarge).
func readDesc(r io.Reader, lim parseLimits) (*DescEntry, error) {
	limited := &limitedReader{r: r, limit: int64(lim.descSize), sentinel: errDescLimit}
	br := newBufReader(limited)
	var entry DescEntry
	var currentField string
	var hasField bool
	lineNo := 0
	for {
		if lineNo >= lim.descLines {
			return nil, ErrDescTooLarge
		}
		line, err := br.readLine()
		if err != nil {
			if errors.Is(err, errDescLimit) {
				return nil, ErrDescTooLarge
			}
			// errDecompressLimit от нижележащего limitedReader — пробрасываем
			// как есть, parseDBTar транслирует в ErrDecompressTooLarge.
			if errors.Is(err, errDecompressLimit) {
				return nil, err
			}
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("pacman: чтение desc: %w", err)
		}
		lineNo++
		// маркер поля: строка вида %FIELD%
		if isFieldMarker(line) {
			currentField = line[1 : len(line)-1]
			hasField = true
			continue
		}
		if !hasField {
			// строка до первого %FIELD% — мусор, игнорируем (tolerant)
			continue
		}
		setDescField(&entry, currentField, line)
	}
	return &entry, nil
}

// isFieldMarker проверяет, что строка имеет вид %FIELD% (маркер поля
// pacman-формата).
func isFieldMarker(line string) bool {
	return len(line) >= 2 && line[0] == '%' && line[len(line)-1] == '%'
}

// setDescField записывает значение в поле DescEntry по имени поля.
// Первое значение выигрывает (дубликаты игнорируются — как и в apk).
// Неизвестные поля игнорируются (forward-compat).
func setDescField(entry *DescEntry, field, line string) {
	switch field {
	case "FILENAME":
		if entry.Filename == "" {
			entry.Filename = strings.TrimSpace(line)
		}
	case "NAME":
		if entry.Name == "" {
			entry.Name = strings.TrimSpace(line)
		}
	case "VERSION":
		if entry.Version == "" {
			entry.Version = strings.TrimSpace(line)
		}
	}
}

// errDecompressLimit — sentinel limitedReader в parseDB: превышен
// декомпресс-лимит (zip-bomb guard). parseDBTar транслирует в
// ErrDecompressTooLarge.
var errDecompressLimit = errors.New("decompress limit exceeded")

// errDescLimit — sentinel limitedReader в readDesc: превышен лимит
// размера одной desc. readDesc транслирует в ErrDescTooLarge.
var errDescLimit = errors.New("desc limit exceeded")

// limitedReader — обёртка, считающая байты и возвращающая sentinel
// при превышении лимита. Не io.LimitReader: последний возвращает io.EOF
// при достижении лимита, что неотличимо от настоящего конца потока;
// здесь нужна именно ошибка с типом (разные sentinel'ы для разных
// лимитов — decompress vs descSize).
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

// bufReader — мини-обёртка над bufio для построчного чтения desc.
// bufio.Reader сам по себе разрастает буфер под длинные строки; здесь
// — простой кэш на 4КиБ, переполнение строки — склейка через Read.
type bufReader struct {
	r   io.Reader
	buf []byte
	pos int
	end int
}

func newBufReader(r io.Reader) *bufReader {
	return &bufReader{r: r, buf: make([]byte, 4096)}
}

func (b *bufReader) readLine() (string, error) {
	var line bytes.Buffer
	for {
		if b.pos >= b.end {
			n, err := b.r.Read(b.buf)
			b.pos = 0
			b.end = n
			if n == 0 && err != nil {
				// отдаем накопленную строку без завершающего \n (tolerant)
				if line.Len() > 0 {
					return line.String(), nil
				}
				return "", err
			}
		}
		for b.pos < b.end {
			c := b.buf[b.pos]
			b.pos++
			if c == '\n' {
				return line.String(), nil
			}
			if c == '\r' {
				continue
			}
			line.WriteByte(c)
		}
	}
}
