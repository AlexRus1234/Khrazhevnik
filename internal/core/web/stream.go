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

// Дедлайны стриминга (аудит 2026-08-27, сессия 27): публичному порту
// WriteTimeout противопоказан (убил бы отдачу больших пакетов) —
// медленный читатель вырубается per-write deadline, каждая запись в
// сокет продлевает дедлайн на writeStallTimeout. Админ-порт, наоборот,
// держит ReadTimeout 30s, который рвал бы upload больших пакетов, —
// тело upload'а продлевает read-deadline перед каждым чтением
// (stallReader).

package web

import (
	"io"
	"net/http"
	"time"
)

// writeStallTimeout — потолок ожидания одной записи в сокет клиента.
// 30 секунд на 32 KiB буфера — это канал медленнее ~1 KiB/s; такой
// клиент отваливается, освобождая FD и tmp-ридер хранилища.
const writeStallTimeout = 30 * time.Second

// uploadStallWindow — окно продления read-deadline на один Read тела
// upload'а. Окно то же, что у стриминга отдачи, и конечное сознательно:
// живой поток продлевает дедлайн каждым чтением, а зависшее чтение —
// клиент умер и молчит — упирается в окно, и соединение закрывается.
// Так анти-slowloris задачи 22 (короткий ReadTimeout админ-сервера)
// сохраняется для мёртвых соединений, не мешая медленным живым.
const uploadStallWindow = writeStallTimeout

// stallWriter — http.ResponseWriter, продлевающий write-deadline
// перед каждой записью. Реальный потолок даёт только боевое соединение
// (ResponseController достаёт *net.Conn); тестовые рекордеры дедлайны
// не поддерживают — ошибка игнорируется, запись идёт как обычно.
type stallWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

// newStallWriter оборачивает w; заголовки и статус идут через
// оригинальный ResponseWriter, deadline — только на тело.
func newStallWriter(w http.ResponseWriter) *stallWriter {
	return &stallWriter{w: w, rc: http.NewResponseController(w)}
}

// Write продлевает дедлайн и пишет тело.
func (s *stallWriter) Write(p []byte) (int, error) {
	_ = s.rc.SetWriteDeadline(time.Now().Add(writeStallTimeout))
	return s.w.Write(p)
}

// stallReader — io.Reader, продлевающий read-deadline перед каждым
// чтением. Зеркало stallWriter для upload: ReadTimeout админ-сервера
// мерит от начала запроса и рвал бы upload большого пакета посреди
// тела (задача 22.2 «админ — JSON-API, стримов нет» была неверна для
// PUT objects). Реальный потолок даёт только боевое соединение;
// тестовые рекордеры дедлайны не поддерживают — ошибка игнорируется,
// чтение идёт как обычно.
type stallReader struct {
	r  io.Reader
	rc *http.ResponseController
}

// newStallReader оборачивает body запроса; ResponseController берётся
// от ResponseWriter — дедлайн ставится на соединение этого запроса.
func newStallReader(w http.ResponseWriter, body io.Reader) *stallReader {
	return &stallReader{r: body, rc: http.NewResponseController(w)}
}

// Read продлевает дедлайн и читает тело.
func (s *stallReader) Read(p []byte) (int, error) {
	_ = s.rc.SetReadDeadline(time.Now().Add(uploadStallWindow))
	return s.r.Read(p)
}
