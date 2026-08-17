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

package testutil

import (
	"context"
	"errors"
	"testing"

	"khrazhevnik/internal/core/domain"
)

func TestFakeUserStoreCRUD(t *testing.T) {
	s := NewFakeUserStore()
	ctx := context.Background()

	if has, err := s.HasUsers(ctx); err != nil || has {
		t.Fatalf("HasUsers на пустом = %v, %v; хочу false, nil", has, err)
	}

	alice, err := s.CreateUser(ctx, domain.User{Username: "alice", Role: domain.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if alice.ID == 0 {
		t.Fatal("CreateUser не назначил ID")
	}
	if _, err := s.CreateUser(ctx, domain.User{Username: "alice"}); !errors.Is(err, &domain.ConflictError{}) {
		t.Fatalf("дубль имени = %v, хочу Conflict", err)
	}

	got, err := s.UserByUsername(ctx, "alice")
	if err != nil || got.ID != alice.ID {
		t.Fatalf("UserByUsername = %+v, %v", got, err)
	}
	if _, err := s.User(ctx, alice.ID); err != nil {
		t.Fatalf("User(%d) = %v", alice.ID, err)
	}
	if _, err := s.User(ctx, 999); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("User(999) = %v, хочу NotFound", err)
	}
	if _, err := s.UserByUsername(ctx, "bob"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("UserByUsername(bob) = %v, хочу NotFound", err)
	}

	bob, err := s.CreateUser(ctx, domain.User{Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	users, err := s.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].ID != alice.ID || users[1].ID != bob.ID {
		t.Errorf("Users = %+v, хочу по возрастанию ID", users)
	}
	if has, _ := s.HasUsers(ctx); !has {
		t.Error("HasUsers после вставок = false")
	}

	alice.Role = domain.RoleUser
	if err := s.UpdateUser(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if updated, _ := s.User(ctx, alice.ID); updated.Role != domain.RoleUser {
		t.Errorf("UpdateUser не применился: %+v", updated)
	}
	if err := s.UpdateUser(ctx, domain.User{ID: 999, Username: "x"}); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("UpdateUser отсутствующего = %v, хочу NotFound", err)
	}
	if err := s.UpdateUser(ctx, domain.User{ID: alice.ID, Username: "bob"}); !errors.Is(err, &domain.ConflictError{}) {
		t.Errorf("переименование в занятое имя = %v, хочу Conflict", err)
	}

	if err := s.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByUsername(ctx, "bob"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("UserByUsername после удаления = %v, хочу NotFound", err)
	}
	if err := s.DeleteUser(ctx, bob.ID); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("повторное удаление = %v, хочу NotFound", err)
	}
}

func TestFakeUserStoreImplementsUserStore(t *testing.T) {
	store := NewFakeUserStore()
	_ = store // компиляционная проверка среза — см. port_test.go
}

func TestFakeObjectIndexImplementsObjectIndex(t *testing.T) {
	index := NewFakeObjectIndex()
	_ = index
}

func TestFakeObjectIndex(t *testing.T) {
	s := NewFakeObjectIndex()
	ctx := context.Background()

	if _, err := s.ObjectMeta(ctx, "cache/apt/1/Release"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("ObjectMeta отсутствующего = %v, хочу NotFound", err)
	}
	m := domain.ObjectMeta{Key: "cache/apt/1/Release", ETag: `"v1"`, Size: 10}
	if err := s.PutObjectMeta(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := s.ObjectMeta(ctx, "cache/apt/1/Release")
	if err != nil || got.ETag != `"v1"` {
		t.Fatalf("ObjectMeta = %+v, %v", got, err)
	}
	// Upsert перезаписывает.
	m.ETag = `"v2"`
	if err := s.PutObjectMeta(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.ObjectMeta(ctx, "cache/apt/1/Release"); got.ETag != `"v2"` {
		t.Errorf("upsert не перезаписал: %+v", got)
	}
	// Delete идемпотентен: отсутствие записи — не ошибка.
	if err := s.DeleteObjectMeta(ctx, "cache/apt/1/Release"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteObjectMeta(ctx, "cache/apt/1/Release"); err != nil {
		t.Errorf("повторное Delete = %v, хочу nil", err)
	}
	if _, err := s.ObjectMeta(ctx, "cache/apt/1/Release"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("ObjectMeta после удаления = %v, хочу NotFound", err)
	}
}
