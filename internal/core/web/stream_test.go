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
	"net/http/httptest"
	"testing"
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
