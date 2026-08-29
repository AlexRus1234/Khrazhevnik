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

package web

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStallWriterPassthrough — рекордер тестов не поддерживает
// write-deadline: stallWriter обязан молча деградировать до обычной
// записи, не роняя стриминг (боевое соединение получает дедлайн).
func TestStallWriterPassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := newStallWriter(rec)
	payload := []byte("package bytes")
	n, err := sw.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v; хочу %d, nil", n, err, len(payload))
	}
	if rec.Body.String() != string(payload) {
		t.Errorf("тело = %q, хочу %q", rec.Body.String(), payload)
	}
}

// TestStallReaderPassthrough — рекордер тестов не поддерживает
// read-deadline: stallReader обязан молча деградировать до обычного
// чтения, не роняя upload (боевое соединение получает дедлайн).
func TestStallReaderPassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	payload := []byte("package bytes")
	sr := newStallReader(rec, bytes.NewReader(payload))
	got, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("тело = %q, хочу %q", got, payload)
	}
}

// deadlineRecorder — рекордер со счётчиком SetReadDeadline: через него
// ResponseController достаёт дедлайны, так что число продлений можно
// посчитать без боевого соединения.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	extends int
}

func (d *deadlineRecorder) SetReadDeadline(time.Time) error {
	d.extends++
	return nil
}

// TestStallReaderExtendsDeadline — каждый Read продлевает
// read-deadline ровно один раз: окно держится, пока поток жив.
func TestStallReaderExtendsDeadline(t *testing.T) {
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	sr := newStallReader(rec, strings.NewReader("ab"))
	buf := make([]byte, 1)
	for i := 0; i < 2; i++ {
		if _, err := sr.Read(buf); err != nil {
			t.Fatalf("Read #%d: %v", i+1, err)
		}
	}
	if rec.extends != 2 {
		t.Errorf("SetReadDeadline вызван %d раз, хочу 2", rec.extends)
	}
}

// dripReader — io.Reader, отдающий тело порциями с паузой перед
// каждой: имитация клиента на троттлинг-канале. ReadTimeout сервера —
// абсолютный дедлайн от начала запроса, так что паузы между порциями
// гарантированно вылезают за него независимо от размера сетевых
// буферов ядра.
type dripReader struct {
	segments int
	segLeft  int
	segSize  int
	interval time.Duration
}

func newDripReader(segSize, segments int, interval time.Duration) *dripReader {
	return &dripReader{segments: segments, segSize: segSize, interval: interval}
}

func (d *dripReader) Read(p []byte) (int, error) {
	if d.segLeft == 0 {
		if d.segments == 0 {
			return 0, io.EOF
		}
		d.segments--
		d.segLeft = d.segSize
		time.Sleep(d.interval)
	}
	n := d.segLeft
	if len(p) < n {
		n = len(p)
	}
	clear(p[:n])
	d.segLeft -= n
	return n, nil
}

// slowUploadServer — httptest-сервер с ReadTimeout=200ms; хендлер —
// заглушка upload'а: тело в stallReader (или голое — контроль) и слив
// в discard, 200 только после полного чтения. Порции по 1 MiB раз в
// 100ms — суммарно ~1.6s, втрое дольше дедлайна.
func slowUploadServer(t *testing.T, stall bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if stall {
			body = newStallReader(w, r.Body)
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ReadTimeout = 200 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestUploadSlowStreamSurvivesReadTimeout — медленный, но живой upload
// не рвётся ReadTimeout'ом админ-сервера: stallReader продлевает
// read-deadline каждым чтением.
func TestUploadSlowStreamSurvivesReadTimeout(t *testing.T) {
	srv := slowUploadServer(t, true)
	req, err := http.NewRequest(http.MethodPut, srv.URL, newDripReader(1<<20, 16, 100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("медленный upload оборвался: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("статус = %d, хочу 200", resp.StatusCode)
	}
}

// TestUploadSlowStreamBreaksWithoutStallReader — контроль: без
// stallReader тот же поток рвётся ReadTimeout'ом сервера, клиент видит
// обрыв соединения посреди тела. Доказывает, что тест выше проверяет
// именно продление дедлайна, а не бездействие таймаутов.
func TestUploadSlowStreamBreaksWithoutStallReader(t *testing.T) {
	srv := slowUploadServer(t, false)
	req, err := http.NewRequest(http.MethodPut, srv.URL, newDripReader(1<<20, 16, 100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("upload прошёл (статус %d), а должен был оборваться по ReadTimeout", resp.StatusCode)
	}
}
