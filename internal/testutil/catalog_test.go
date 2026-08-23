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
	"time"

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

func TestFakeRemoteStoreImplementsRemoteStore(t *testing.T) {
	_ = NewFakeRemoteStore()
}

func TestFakeRepoStoreImplementsRepoStore(t *testing.T) {
	_ = NewFakeRepoStore()
}

func TestFakeJobStoreImplementsJobStore(t *testing.T) {
	_ = NewFakeJobStore()
}

func TestFakeAuditLogImplementsAuditLog(t *testing.T) {
	_ = NewFakeAuditLog()
}

func TestFakeAuditLogPagination(t *testing.T) {
	log := NewFakeAuditLog()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := log.Record(ctx, domain.AuditEntry{Actor: "x", Action: "y", Object: "z", Result: domain.AuditOK}); err != nil {
			t.Fatal(err)
		}
	}
	if got := log.Len(); got != 5 {
		t.Fatalf("Len = %d, хочу 5", got)
	}
	page, err := log.AuditEntries(ctx, 0, 3)
	if err != nil || len(page) != 3 {
		t.Fatalf("страница 1 = %d, %v", len(page), err)
	}
	page2, err := log.AuditEntries(ctx, page[2].ID, 3)
	if err != nil || len(page2) != 2 {
		t.Fatalf("страница 2 = %d, %v", len(page2), err)
	}
	// default limit.
	all, err := log.AuditEntries(ctx, 0, 0)
	if err != nil || len(all) != 5 {
		t.Fatalf("default limit = %d, хочу 5", len(all))
	}
}

func TestFakeRepoStoreCRUD(t *testing.T) {
	s := NewFakeRepoStore()
	ctx := context.Background()
	r, err := s.CreateRepo(ctx, domain.Repo{Name: "myrepo", Ecosystem: "apt"})
	if err != nil || r.ID == 0 {
		t.Fatal(err)
	}
	if _, err := s.CreateRepo(ctx, domain.Repo{Name: "myrepo"}); !errors.Is(err, &domain.ConflictError{}) {
		t.Fatalf("дубль = %v, хочу Conflict", err)
	}
	got, err := s.Repo(ctx, r.ID)
	if err != nil || got.Name != "myrepo" {
		t.Fatalf("Repo = %+v, %v", got, err)
	}
	if _, err := s.Repo(ctx, 999); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("Repo(999) = %v, хочу NotFound", err)
	}
	r.Ecosystem = "rpm-md"
	if err := s.UpdateRepo(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRepo(ctx, domain.Repo{ID: 999, Name: "x"}); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("Update отсутствующего = %v", err)
	}
	if rs, _ := s.Repos(ctx); len(rs) != 1 || rs[0].Ecosystem != "rpm-md" {
		t.Errorf("Repos = %+v", rs)
	}
	// Perms.
	if err := s.Grant(ctx, domain.Perm{RepoID: r.ID, UserID: 1, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(ctx, domain.Perm{RepoID: r.ID, UserID: 1}); err != nil {
		t.Fatal(err) // идемпотентен
	}
	ps, _ := s.Perms(ctx, r.ID)
	if len(ps) != 1 || ps[0].UserID != 1 {
		t.Errorf("Perms = %+v", ps)
	}
	if err := s.Revoke(ctx, r.ID, 1); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.Perms(ctx, r.ID); len(ps) != 0 {
		t.Errorf("Perms после Revoke = %+v", ps)
	}
	if err := s.DeleteRepo(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRepo(ctx, r.ID); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("повторное Delete = %v", err)
	}
}

func TestFakeJobStoreCRUD(t *testing.T) {
	s := NewFakeJobStore()
	ctx := context.Background()
	j, err := s.CreateJob(ctx, domain.SyncJob{RemoteID: 1, State: domain.StatePending})
	if err != nil || j.ID == 0 {
		t.Fatal(err)
	}
	got, err := s.Job(ctx, j.ID)
	if err != nil || got.RemoteID != 1 {
		t.Fatalf("Job = %+v, %v", got, err)
	}
	if _, err := s.Job(ctx, 999); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("Job(999) = %v", err)
	}
	j.State = domain.StateRunning
	if err := s.UpdateJob(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateJob(ctx, domain.SyncJob{ID: 999}); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("Update отсутствующей = %v", err)
	}
	if js, _ := s.Jobs(ctx); len(js) != 1 || js[0].State != domain.StateRunning {
		t.Errorf("Jobs = %+v", js)
	}
	if err := s.DeleteJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteJob(ctx, j.ID); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("повторное Delete = %v", err)
	}
}

func TestFakeRemoteStoreImplementsRemoteStoreCRUD(t *testing.T) {
	// Небольшой smoke: CRUD фейка remotes (не повторяем catalog_test
	// целиком — он покрыт UserStore).
	s := NewFakeRemoteStore()
	ctx := context.Background()
	r, err := s.CreateRemote(ctx, domain.Remote{Name: "debian", Ecosystem: "apt", BaseURL: "https://x"})
	if err != nil || r.ID == 0 {
		t.Fatal(err)
	}
	if got, _ := s.Remote(ctx, r.ID); got.Name != "debian" {
		t.Errorf("Remote = %+v", got)
	}
	if _, err := s.Remote(ctx, 999); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("Remote(999) = %v", err)
	}
	r.BaseURL = "https://y"
	if err := s.UpdateRemote(ctx, r); err != nil {
		t.Fatal(err)
	}
	if rs, _ := s.Remotes(ctx); len(rs) != 1 || rs[0].BaseURL != "https://y" {
		t.Errorf("Remotes = %+v", rs)
	}
	if err := s.DeleteRemote(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRemote(ctx, r.ID); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("повторное Delete = %v", err)
	}
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
