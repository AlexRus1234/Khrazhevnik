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

package cache

import (
	"sync"
	"time"
)

// Txn — запись клиентской транзакции кеша для операционной панели
// («что происходит», не аудит): время, экосистема, путь, исход
// (HIT|MISS|STALE|error), размер, текст ошибки.
type Txn struct {
	At        time.Time
	Ecosystem string
	Path      string
	Status    string
	Size      int64
	Err       string
}

// txnCap — глубина истории клиентских транзакций. Bounded-память:
// всплеск запросов не растит движок, старое вытесняется.
const txnCap = 50

// Потолки длины строк записи: пути и тексты ошибок бывают мегабайтными
// (сканеры, битые upstream) — история такого не держит.
const (
	txnPathRunes = 200
	txnErrRunes  = 256
)

// txnLog — кольцевой буфер последних клиентских транзакций: O(1)
// запись, чтение копией newest-first. In-memory и без persist —
// осознанно (прецедент TaskRegistry), постоянный журнал — пост-v1.
type txnLog struct {
	mu    sync.Mutex
	ring  [txnCap]Txn
	head  int // позиция следующей записи
	count int
}

// record кладёт транзакцию в кольцо. Пустой статус при ошибке
// нормализуется в "error" (клиентская ветка не успела дать HIT/MISS/
// STALE — исход всё равно ошибочный); непустой проходит как есть.
func (l *txnLog) record(txn Txn) {
	if txn.Status == "" && txn.Err != "" {
		txn.Status = "error"
	}
	txn.Path = truncateRunes(txn.Path, txnPathRunes)
	txn.Err = truncateRunes(txn.Err, txnErrRunes)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring[l.head] = txn
	l.head = (l.head + 1) % txnCap
	if l.count < txnCap {
		l.count++
	}
}

// recent возвращает последние limit записей, newest-first, копией
// (читателю безопасно пользоваться слайсом, пока пишутся новые).
func (l *txnLog) recent(limit int) []Txn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit < 0 {
		limit = 0
	}
	if limit > l.count {
		limit = l.count
	}
	if limit > txnCap {
		limit = txnCap
	}
	out := make([]Txn, limit)
	for i := 0; i < limit; i++ {
		idx := (l.head - 1 - i + txnCap) % txnCap
		out[i] = l.ring[idx]
	}
	return out
}

// truncateRunes режет строку до n рун (многобайтные пути не рвутся
// посреди байта UTF-8).
func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// errText — строка ошибки для записи (nil — пустая строка).
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
