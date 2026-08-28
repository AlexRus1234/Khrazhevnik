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

// Write-deadline для стриминг-хендлеров публичного порта (аудит
// 2026-08-27): сервер без WriteTimeout (иначе умирает стриминг больших
// пакетов), поэтому медленный читатель вырубается per-write deadline —
// каждая запись в сокет продлевает дедлайн на writeStallTimeout.

package web

import (
	"net/http"
	"time"
)

// writeStallTimeout — потолок ожидания одной записи в сокет клиента.
// 30 секунд на 32 KiB буфера — это канал медленнее ~1 KiB/s; такой
// клиент отваливается, освобождая FD и tmp-ридер хранилища.
const writeStallTimeout = 30 * time.Second

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
