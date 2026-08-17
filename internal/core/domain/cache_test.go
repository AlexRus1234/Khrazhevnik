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

package domain

import (
	"errors"
	"testing"
	"time"
)

func TestClassConstructors(t *testing.T) {
	if got := Immutable(); got.Kind != KindImmutable {
		t.Errorf("Immutable().Kind = %q, хочу %q", got.Kind, KindImmutable)
	}
	ttl := 5 * time.Minute
	if got := Mutable(ttl); got.Kind != KindMutable || got.TTL != ttl {
		t.Errorf("Mutable(%v) = %+v", ttl, got)
	}
}

func TestClassValidate(t *testing.T) {
	tests := []struct {
		c    Class
		want bool
	}{
		{Immutable(), true},
		{Mutable(time.Second), true},
		{Class{}, false},                                   // неизвестный вид
		{Class{Kind: "mutable!"}, false},                   // мусорный вид
		{Mutable(0), false},                                // mutable без TTL
		{Mutable(-time.Second), false},                     // отрицательный TTL
		{Class{Kind: KindImmutable, TTL: time.Hour}, true}, // TTL у immutable игнорируется
	}
	for _, tc := range tests {
		err := tc.c.Validate()
		if tc.want && err != nil {
			t.Errorf("Class(%+v).Validate() = %v, хочу nil", tc.c, err)
		}
		if !tc.want {
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("Class(%+v).Validate() = %v, хочу *ValidationError", tc.c, err)
			}
		}
	}
}

func TestObjectMetaExpired(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		expiresAt time.Time
		at        time.Time
		want      bool
	}{
		{time.Time{}, now, false},                          // бессрочно
		{now.Add(time.Hour), now, false},                   // ещё свежо
		{now.Add(-time.Hour), now, true},                   // протухло
		{now, now, true},                                   // ровно в момент истечения
		{now.Add(time.Hour), now.Add(2 * time.Hour), true}, // истекло между проверками
	}
	for _, tc := range tests {
		m := ObjectMeta{Key: "k", ExpiresAt: tc.expiresAt}
		if got := m.Expired(tc.at); got != tc.want {
			t.Errorf("Expired(at=%v) c ExpiresAt=%v = %v, хочу %v", tc.at, tc.expiresAt, got, tc.want)
		}
	}
}
