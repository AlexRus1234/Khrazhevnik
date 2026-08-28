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

// Потоковый ограничитель полосы (Throttle, аудит 2026-08-27): байты
// оплачиваются по мере копирования, ошибка оплаты — прерывание без
// коммита объекта.

package cache

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestPrefetchThrottledPaysAsItCopies — каждый байт, ушедший в
// хранилище, оплачен wait'ом; HIT второго вызова бесплатен.
func TestPrefetchThrottledPaysAsItCopies(t *testing.T) {
	body := strings.Repeat("x", 10000)
	env := newTestEnv(t, defaultConfig(), fixedHandler(body, "application/octet-stream"))

	var mu sync.Mutex
	var waited int64
	wait := func(_ context.Context, n int) error {
		mu.Lock()
		waited += int64(n)
		mu.Unlock()
		return nil
	}
	res, err := env.engine.PrefetchThrottled(context.Background(), env.eco, "/pkg/a.deb", wait)
	if err != nil {
		t.Fatalf("PrefetchThrottled: %v", err)
	}
	if res.Status != statusMiss {
		t.Errorf("статус = %s, хочу MISS", res.Status)
	}
	mu.Lock()
	paid := waited
	mu.Unlock()
	if paid != int64(len(body)) {
		t.Errorf("оплачено %d байт, скачано %d", paid, len(body))
	}

	// второй prefetch — HIT: ничего не качается, плата нулевая
	mu.Lock()
	waited = 0
	mu.Unlock()
	res, err = env.engine.PrefetchThrottled(context.Background(), env.eco, "/pkg/a.deb", wait)
	if err != nil {
		t.Fatalf("повторный PrefetchThrottled: %v", err)
	}
	if res.Status != statusHit {
		t.Errorf("повторный статус = %s, хочу HIT", res.Status)
	}
	mu.Lock()
	paid = waited
	mu.Unlock()
	if paid != 0 {
		t.Errorf("HIT оплачен %d байтами, хочу 0", paid)
	}
}

// TestPrefetchThrottledWaitErrorAborts — ошибка оплаты (например,
// отмена ctx при остановке) прерывает копирование: объект не
// коммитится, upstream-тело выбрасывается.
func TestPrefetchThrottledWaitErrorAborts(t *testing.T) {
	body := strings.Repeat("x", 10000)
	env := newTestEnv(t, defaultConfig(), fixedHandler(body, "application/octet-stream"))

	wait := func(_ context.Context, _ int) error { return context.Canceled }
	if _, err := env.engine.PrefetchThrottled(context.Background(), env.eco, "/pkg/a.deb", wait); err == nil {
		t.Fatal("ошибка wait должна прервать prefetch с ошибкой")
	}
	if _, err := env.storage.Stat(context.Background(), "cache/t/pkg/a.deb"); err == nil {
		t.Error("объект закоммичен вопреки ошибке оплаты")
	}
}
