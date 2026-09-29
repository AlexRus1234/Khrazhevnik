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

package sqlite

import (
	"context"
	"errors"
	"iter"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
)

// TestAccessMergeRoundtrip — юнит object_access на :memory: (контракт
// на трёх драйверах — общий suite, postgres/mariadb в CI): мёрж батча →
// MAX-семантика времени и сложение hits → префикс с «_» — литерал →
// пустой батч — no-op → NotFound на точечном луке.
func TestAccessMergeRoundtrip(t *testing.T) {
	ctx := context.Background()
	st := openDSN(t, ":memory:")

	collect := func(scope, prefix string) []domain.ObjectAccess {
		t.Helper()
		seq, err := st.AccessByPrefix(ctx, scope, prefix)
		if err != nil {
			t.Fatalf("AccessByPrefix(%q, %q): %v", scope, prefix, err)
		}
		var out []domain.ObjectAccess
		for a, err := range seq {
			if err != nil {
				t.Fatalf("обход обращений: %v", err)
			}
			out = append(out, a)
		}
		return out
	}

	if got := collect(domain.AccessScopeRepo, "repo/7/"); len(got) != 0 {
		t.Fatalf("обращения на пустой таблице = %+v, хочу пусто", got)
	}
	if err := st.MergeAccess(ctx, nil); err != nil {
		t.Fatalf("пустой срез — no-op: %v", err)
	}

	first := []domain.ObjectAccess{
		{Scope: domain.AccessScopeRepo, Key: "repo/7/apt/lib_foo_1.0_amd64.deb", LastAccess: fixed, Hits: 2},
		{Scope: domain.AccessScopeRepo, Key: "repo/7/apt/libXfoo_1.0_amd64.deb", LastAccess: fixed, Hits: 9},
		{Scope: domain.AccessScopeCache, Key: "cache/apt/1/lib_foo_1.0_amd64.deb", LastAccess: fixed, Hits: 4},
	}
	if err := st.MergeAccess(ctx, first); err != nil {
		t.Fatalf("MergeAccess: %v", err)
	}

	got := collect(domain.AccessScopeRepo, "repo/7/apt/lib_foo_")
	if len(got) != 1 || got[0] != first[0] {
		t.Fatalf("префикс с «_» вернул %+v, хочу одну запись %+v", got, first[0])
	}
	if got := collect(domain.AccessScopeCache, "cache/apt/"); len(got) != 1 || got[0].Hits != 4 {
		t.Fatalf("cache-скоуп вернул %+v, хочу одну запись с hits=4", got)
	}

	// Повторный мёрж со СТАРЫМ временем: время не откатывается, hits
	// складываются (MAX-семантика — иначе старые обращения обнуляли бы
	// давность, и ретеншн удалял бы живую версию).
	if err := st.MergeAccess(ctx, []domain.ObjectAccess{
		{Scope: domain.AccessScopeRepo, Key: "repo/7/apt/lib_foo_1.0_amd64.deb", LastAccess: fixed.Add(-48 * time.Hour), Hits: 3},
	}); err != nil {
		t.Fatalf("повторный MergeAccess: %v", err)
	}
	entry, err := st.AccessEntry(ctx, domain.AccessScopeRepo, "repo/7/apt/lib_foo_1.0_amd64.deb")
	if err != nil {
		t.Fatalf("AccessEntry: %v", err)
	}
	if !entry.LastAccess.Equal(fixed) {
		t.Fatalf("время обращения = %v, хочу %v (не откатывается)", entry.LastAccess, fixed)
	}
	if entry.Hits != 5 {
		t.Fatalf("hits = %d, хочу 5 (2+3)", entry.Hits)
	}

	// Пустой батч — no-op: ни строк, ни счётчиков.
	if err := st.MergeAccess(ctx, []domain.ObjectAccess{}); err != nil {
		t.Fatalf("пустой батч — no-op: %v", err)
	}
	if got := collect(domain.AccessScopeRepo, "repo/7/"); len(got) != 2 {
		t.Fatalf("после пустого батча записей %d, хочу 2: %+v", len(got), got)
	}
	entry, err = st.AccessEntry(ctx, domain.AccessScopeRepo, "repo/7/apt/lib_foo_1.0_amd64.deb")
	if err != nil || entry.Hits != 5 {
		t.Fatalf("мёрж после пустого батча изменил строку: %+v, %v", entry, err)
	}

	_, err = st.AccessEntry(ctx, domain.AccessScopeRepo, "repo/7/apt/nope.deb")
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("AccessEntry отсутствующего = %v, хочу *domain.NotFoundError", err)
	}
}

// TestAccessByPrefixTerminalError — префиксное чтение обязано быть
// терминальным: ошибка в потоке не превращается в молчаливо-пустой
// обход (потребитель — ретеншн: «обращений нет» и «не удалось прочесть»
// не одно и то же). Закрытая БД — детерминированный сбой без внешних
// сервисов.
func TestAccessByPrefixTerminalError(t *testing.T) {
	ctx := context.Background()
	st := openDSN(t, ":memory:")
	if err := st.MergeAccess(ctx, []domain.ObjectAccess{
		{Scope: domain.AccessScopeRepo, Key: "repo/7/apt/a.deb", LastAccess: fixed, Hits: 1},
	}); err != nil {
		t.Fatalf("MergeAccess: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	seq, err := st.AccessByPrefix(ctx, domain.AccessScopeRepo, "repo/7/")
	if err == nil {
		err = drainAccess(seq)
	}
	if err == nil {
		t.Fatal("обход на закрытой БД не вернул терминальной ошибки")
	}
}

// drainAccess исчерпывает последовательность обращений, возвращая первую
// ошибку.
func drainAccess(seq iter.Seq2[domain.ObjectAccess, error]) error {
	for _, err := range seq {
		if err != nil {
			return err
		}
	}
	return nil
}
