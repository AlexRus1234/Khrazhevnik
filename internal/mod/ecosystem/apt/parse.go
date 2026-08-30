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

// Stanza-парсер RFC822-style (deb822): Packages/Sources/Release.
// Потоковый: не грузит файл целиком, отдаёт записи по одной через
// iter.Seq2. Бесконечный ввод ограничен потолками числа записей и
// размера поля — парсер не паникует и не зацикливается на
// противоречивом/битом вводе (фаззинг — сессия 07). Без I/O: принимает
// io.Reader, стримит через bufio; переиспользуется зеркалом (сессия
// 11) и фаззингом.

package apt

import (
	"bufio"
	"errors"
	"io"
	"iter"
	"strings"
)

// Потолки для защиты от adversarial-ввода (фаззинг): один безумный
// ввод не должен сожрать память или повиснуть. Значения покрывают
// реальные Packages (Debian main — сотни тысяч записей, Description
// до килобайт) с запасом.
const (
	maxStanzas    = 1 << 20 // 1 млн записей
	maxFieldValue = 1 << 20 // 1 МБ на одно значение
	maxFieldName  = 1 << 14 // 16 КБ на имя поля (реальные — десятки байт)
)

// Ошибки парсера — типизированные, чтобы фаззинг мог отличить
// структурный сбой от границы ввода; сравнение через errors.Is.
var (
	ErrTooManyStanzas   = errors.New("apt: слишком много записей")
	ErrFieldTooLong     = errors.New("apt: поле превысило лимит")
	ErrFieldNameTooLong = errors.New("apt: имя поля превысило лимит")
	ErrNoColon          = errors.New("apt: строка без «:» и не продолжение")
)

// Stanza — одна запись: отображение Field → value с сохранением
// порядка первого вписывания (детерминированный дамп в тестах).
// Значения хранят raw bytes (Go-строка — []byte под капотом), что
// позволяет держать невалидный UTF-8 без перекодирования.
type Stanza struct {
	keys []string
	vals map[string]string
}

// newStanza создаёт пустую запись.
func newStanza() *Stanza { return &Stanza{vals: map[string]string{}} }

// Set добавляет или перезаписывает поле; первая вписанная версия
// запоминает порядок.
func (s *Stanza) Set(name, value string) {
	if _, ok := s.vals[name]; !ok {
		s.keys = append(s.keys, name)
	}
	s.vals[name] = value
}

// Get возвращает значение поля; пустая строка — поля нет.
func (s *Stanza) Get(name string) string { return s.vals[name] }

// Keys — имена полей в порядке первого появления.
func (s *Stanza) Keys() []string { return s.keys }

// Len — число полей.
func (s *Stanza) Len() int { return len(s.keys) }

// Equal сообщает эквивалентность двух записей: тот же набор полей и
// значений. Порядок ключей игнорируется — парсер и так детерминирован,
// но эквивалентность удобнее без учёта порядка.
func (s *Stanza) Equal(o *Stanza) bool {
	if s == nil || o == nil {
		return s == o
	}
	if s.Len() != o.Len() {
		return false
	}
	for k, v := range s.vals {
		if o.vals[k] != v {
			return false
		}
	}
	return true
}

// Stanzas возвращает итератор по записям потока. Ошибка прерывает
// обход и отдаётся последним yield'ом (запись nil). Чистый EOF —
// тихое завершение; незавершённая запись без финальной пустой строки
// тоже отдаётся (tolerant к файлам без завершающего \n\n).
//
// Формат: «Field: value», продолжение строки — ведущий пробел/tab;
// разделитель записей — пустая строка. CRLF срезается; невалидный
// UTF-8 сохраняется в значении как raw bytes.
func Stanzas(r io.Reader) iter.Seq2[*Stanza, error] {
	return stanzas(r, limits{stanzas: maxStanzas, field: maxFieldValue, name: maxFieldName})
}

// limits — потолки парсера. Вынесены в структуру, чтобы тесты
// прогоняли границу числа записей на маленьких значениях (1 млн
// реальных записей — секунды, фаззингу и модулю это ни к чему).
type limits struct {
	stanzas int
	field   int
	name    int
}

func stanzas(r io.Reader, lim limits) iter.Seq2[*Stanza, error] {
	return func(yield func(*Stanza, error) bool) {
		br := bufio.NewReader(r)
		cur := newStanza()
		var lastName string
		count := 0
		for {
			line, err := readLine(br, lim.field+lim.name+2)
			eof := errors.Is(err, io.EOF)
			if err != nil && !eof {
				_ = yield(nil, err)
				return
			}
			cont, stop := processLine(line, cur, &lastName, lim)
			if stop != nil {
				_ = yield(nil, stop)
				return
			}
			if cont {
				// запись завершена — отдаём и начинаем новую.
				// count — число уже отданных; lim.stanzas — максимум,
				// поэтому >= (а не >) ловит (max+1)-ю вовремя.
				if count >= lim.stanzas {
					_ = yield(nil, ErrTooManyStanzas)
					return
				}
				if !yield(cur, nil) {
					return
				}
				count++
				cur = newStanza()
				lastName = ""
			}
			if eof {
				if cur.Len() > 0 {
					if count >= lim.stanzas {
						_ = yield(nil, ErrTooManyStanzas)
						return
					}
					_ = yield(cur, nil)
				}
				return
			}
		}
	}
}

// readLine читает одну строку с потолком max и возвращает её без
// финального \n и \r\n. ReadString('\n') буферизовал бы строку
// целиком ДО проверки лимита — гигабайтная строка без \n съедала
// память до отказа (OOM-путь аудита 2026-08-30), поэтому лимит
// проверяется В ПРОЦЕССЕ чтения: строка длиннее max (или EOF-хвост
// длиннее max) → ErrFieldTooLong немедленно, после ~max прочитанного,
// а не после полного буфера. max — lim.field+lim.name+2: строка-поле
// длиннее этого перелимитна либо по значению, либо по имени —
// processLine отклонил бы её всё равно, ранний отказ не сужает
// множество принимаемых вводов. Возвращает io.EOF, когда поток
// исчерпан (line при этом может содержать хвост без завершающего
// перевода — отдаётся как последняя строка). Проглатывание io.EOF
// здесь было бы вечным циклом: итератор не узнал бы о конце потока.
// Контракт (line, err) не меняется.
func readLine(br *bufio.Reader, max int) (string, error) {
	var buf []byte
	for {
		slice, err := br.ReadSlice('\n')
		switch {
		case err == nil:
			// \n найден: срезаем его и собираем строку из кусков.
			line := slice[:len(slice)-1]
			if len(buf) > 0 {
				buf = append(buf, line...)
				line = buf
			}
			return strings.TrimSuffix(string(line), "\r"), nil
		case errors.Is(err, bufio.ErrBufferFull):
			// строка длиннее буфера bufio — копим куски до max.
			if len(buf)+len(slice) > max {
				return "", ErrFieldTooLong
			}
			buf = append(buf, slice...)
		case errors.Is(err, io.EOF):
			// \n не встретился: хвост без перевода — последняя
			// строка; EOF обязан дойти до итератора.
			if len(buf)+len(slice) > max {
				return "", ErrFieldTooLong
			}
			buf = append(buf, slice...)
			return strings.TrimSuffix(string(buf), "\r"), io.EOF
		default:
			return "", err
		}
	}
}

// processLine разбирает одну строку и обновляет текущую запись.
// Возвращает (completed, stopErr): completed=true — запись готова к
// выдаче (строка была пустой и в записи уже есть поля); stopErr!=nil —
// предел достигнут, обход надо прекратить с ошибкой.
func processLine(line string, cur *Stanza, lastName *string, lim limits) (bool, error) {
	// пустая строка — разделитель записей
	if line == "" {
		if cur.Len() == 0 {
			// подряд идущие пустые — игнорируем (нет записи к выдаче)
			return false, nil
		}
		return true, nil
	}
	// продолжение многострочного поля: ведущий пробел/tab
	if line[0] == ' ' || line[0] == '\t' {
		if *lastName == "" {
			// продолжение без поля — структурный сбой; tolerant:
			// игнорируем строку, не падая на чужом формате
			return false, nil
		}
		v := cur.Get(*lastName)
		// fold deb822: срезаем один ведущий пробел (маркер
		// продолжения), остальное — содержимое; строки склеиваем
		// переводом строки, как делает dpkg. Так multiline
		// Description сохраняет структуру абзаца.
		cont := line[1:]
		joined := v + "\n" + cont
		if len(joined) > lim.field {
			return false, ErrFieldTooLong
		}
		cur.Set(*lastName, joined)
		return false, nil
	}
	// новая строка-поле: «Name: value»
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return false, ErrNoColon
	}
	name := line[:idx]
	if len(name) > lim.name {
		return false, ErrFieldNameTooLong
	}
	// значение после «: » (один пробел срезается; без пробела — пусто)
	val := line[idx+1:]
	val = strings.TrimPrefix(val, " ")
	if len(val) > lim.field {
		return false, ErrFieldTooLong
	}
	cur.Set(name, val)
	*lastName = name
	return false, nil
}
