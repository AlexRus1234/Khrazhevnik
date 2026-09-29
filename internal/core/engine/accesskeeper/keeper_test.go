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

package accesskeeper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

var fixedNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

// TestRecordFlushMerge — два обращения к одному объекту сливаются в
// одну строку: hits=2, время — от port.Clock (правило port.Clock).
func TestRecordFlushMerge(t *testing.T) {
	store := testutil.NewFakeAccessStore()
	k := New(store, testutil.FixedClock(fixedNow), time.Minute)

	k.Record(domain.AccessScopeRepo, "repo/7/apt/pool/main/h/htop/htop_3.deb")
	k.Record(domain.AccessScopeRepo, "repo/7/apt/pool/main/h/htop/htop_3.deb")
	if err := k.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	merges := store.Merges()
	if len(merges) != 1 {
		t.Fatalf("мёржей %d, хочу 1: %+v", len(merges), merges)
	}
	if len(merges[0]) != 1 {
		t.Fatalf("в батче %d строк, хочу 1: %+v", len(merges[0]), merges[0])
	}
	row := merges[0][0]
	if row.Scope != domain.AccessScopeRepo || row.Key != "repo/7/apt/pool/main/h/htop/htop_3.deb" {
		t.Errorf("строка батча = %+v", row)
	}
	if row.Hits != 2 {
		t.Errorf("hits = %d, хочу 2 (два Record одного объекта)", row.Hits)
	}
	if !row.LastAccess.Equal(fixedNow) {
		t.Errorf("LastAccess = %v, хочу %v", row.LastAccess, fixedNow)
	}
}

// TestFlushEmpty — без обращений флаш не ходит в БД (пустой батч —
// no-op, как у адаптера и фейка).
func TestFlushEmpty(t *testing.T) {
	store := testutil.NewFakeAccessStore()
	k := New(store, testutil.FixedClock(fixedNow), time.Minute)

	if err := k.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Merges()); got != 0 {
		t.Errorf("пустая карта дала %d мёржей, хочу 0", got)
	}
}

// TestRecordKeepsMaxTime — контракт MAX: откат часов назад не
// омолаживает объект (давность обращения — критерий удаления
// ретеншна, «омоложение» продлило бы жизнь версии).
func TestRecordKeepsMaxTime(t *testing.T) {
	store := testutil.NewFakeAccessStore()
	clock := testutil.NewManualClock(fixedNow)
	k := New(store, clock, time.Minute)
	const key = "cache/apt/1/pool/main/h/htop/htop_3.deb"

	k.Record(domain.AccessScopeCache, key)
	clock.Advance(time.Minute) // время второго обращения — самое позднее
	k.Record(domain.AccessScopeCache, key)
	clock.Advance(-30 * time.Minute) // часы ушли назад (сводка NTP)
	k.Record(domain.AccessScopeCache, key)

	if err := k.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	merges := store.Merges()
	if len(merges) != 1 || len(merges[0]) != 1 {
		t.Fatalf("мёржи = %+v, хочу один батч из одной строки", merges)
	}
	row := merges[0][0]
	if !row.LastAccess.Equal(fixedNow.Add(time.Minute)) {
		t.Errorf("LastAccess = %v, хочу %v (время не откатывается назад)",
			row.LastAccess, fixedNow.Add(time.Minute))
	}
	if row.Hits != 3 {
		t.Errorf("hits = %d, хочу 3", row.Hits)
	}
}

// TestRunStop — тикер мёржит по интервалу, Stop гасит горутину, делает
// финальный флаш и идемпотентен. Обращения, поданные между тиками,
// доезжают до БД целиком: сумма hits по всем батчам = числу Record.
func TestRunStop(t *testing.T) {
	store := testutil.NewFakeAccessStore()
	k := New(store, testutil.FixedClock(fixedNow), 20*time.Millisecond)
	k.Run(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	recorded := 0
	for len(store.Merges()) < 2 { // тик-флаш виден только при непустой карте
		if time.Now().After(deadline) {
			t.Fatalf("за 2s тикер дал %d мёржей, хочу ≥2", len(store.Merges()))
		}
		k.Record(domain.AccessScopeRepo, fmt.Sprintf("repo/1/apt/obj-%d.deb", recorded))
		recorded++
		time.Sleep(5 * time.Millisecond)
	}
	// Непустая карта к моменту Stop — финальный флаш виден в истории.
	k.Record(domain.AccessScopeRepo, "repo/1/apt/final.deb")
	recorded++

	if err := k.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	merges := store.Merges()
	if len(merges) < 3 {
		t.Errorf("после Stop %d мёржей (≥2 тика + финальный), хочу ≥3", len(merges))
	}
	var hits int64
	for _, batch := range merges {
		for _, row := range batch {
			hits += row.Hits
		}
	}
	if hits != int64(recorded) {
		t.Errorf("до БД доехало %d обращений, подано %d (потеря в окне тика)", hits, recorded)
	}

	// Повторный Stop — идемпотентен: тикер погашен, карта пуста, новой
	// записи в БД нет.
	before := len(merges)
	if err := k.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Merges()); got != before {
		t.Errorf("повторный Stop дал %d мёржей вместо %d", got, before)
	}
}

// TestRecordCapDropped — потолок карты: сверх 100k новых ключей
// обращения не аккредитуются и считаются dropped, флаш при этом
// цел (защита памяти от сканера не ломает запись накопленного).
func TestRecordCapDropped(t *testing.T) {
	store := testutil.NewFakeAccessStore()
	k := New(store, testutil.FixedClock(fixedNow), time.Minute)

	for i := 0; i <= maxKeys; i++ {
		k.Record(domain.AccessScopeCache, fmt.Sprintf("cache/apt/1/pool/pkg-%d.deb", i))
	}
	if got := k.Dropped(); got < 1 {
		t.Errorf("dropped = %d при %d ключах, хочу ≥1", got, maxKeys+1)
	}

	if err := k.Flush(context.Background()); err != nil {
		t.Fatalf("флаш переполненной карты: %v", err)
	}
	merges := store.Merges()
	if len(merges) != 1 {
		t.Fatalf("мёржей %d, хочу 1", len(merges))
	}
	if len(merges[0]) != maxKeys {
		t.Errorf("в батче %d строк, хочу %d (новые сверх потолка не аккредитованы)",
			len(merges[0]), maxKeys)
	}
	// Счётчик отброшенного — за окно: после флаша карта снова свободна.
	if got := k.Dropped(); got != 0 {
		t.Errorf("dropped после флаша = %d, хочу 0", got)
	}
	k.Record(domain.AccessScopeCache, "cache/apt/1/pool/pkg-fresh.deb")
	if err := k.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Merges()); got != 2 {
		t.Errorf("после сброса потолка мёржей %d, хочу 2 (новый ключ аккредитован)", got)
	}
}
