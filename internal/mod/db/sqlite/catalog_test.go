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
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Компиляция срезов порта: Store обязан реализовать весь каталог.
var (
	_ port.UserStore   = (*Store)(nil)
	_ port.TokenStore  = (*Store)(nil)
	_ port.RepoStore   = (*Store)(nil)
	_ port.RemoteStore = (*Store)(nil)
	_ port.JobStore    = (*Store)(nil)
	_ port.AuditLog    = (*Store)(nil)
	_ port.ObjectIndex = (*Store)(nil)
)

// fixed — детерминированное время записи (эпоха теряет доли секунды —
// сравнение после Unix()-нормализации).
var fixed = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// openTest — файловая БД во временном каталоге (изоляция тестов,
// проверка WAL/пула на реальном носителе).
func openTest(t *testing.T) *Store {
	t.Helper()
	return openDSN(t, filepath.Join(t.TempDir(), "test.db"))
}

// openDSN — Store по произвольному DSN.
func openDSN(t *testing.T, dsn string) *Store {
	t.Helper()
	st, err := Open(config.Database{DSN: dsn})
	if err != nil {
		t.Fatalf("Open(%s): %v", dsn, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// wantNotFound/wantConflict — общие ассерты доменных ошибок.
func wantNotFound(t *testing.T, err error) {
	t.Helper()
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("хочу NotFoundError, получено: %v", err)
	}
}

func wantConflict(t *testing.T, err error) {
	t.Helper()
	var cf *domain.ConflictError
	if !errors.As(err, &cf) {
		t.Fatalf("хочу ConflictError, получено: %v", err)
	}
}

func TestBuildDSN(t *testing.T) {
	cases := []struct{ name, dsn, wantSubstr string }{
		{"путь", "/var/lib/x.db", "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"},
		{"file-uri с запросом", "file:x?mode=memory&cache=shared", "&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"},
	}
	for _, c := range cases {
		got := buildDSN(c.dsn, 42)
		if !strings.Contains(got, c.wantSubstr) {
			t.Fatalf("%s: buildDSN = %q, не содержит %q", c.name, got, c.wantSubstr)
		}
	}
	mem := buildDSN(":memory:", 42)
	if !strings.Contains(mem, "file:mem-42?mode=memory&cache=shared") {
		t.Fatalf("память: buildDSN = %q", mem)
	}
	if buildDSN(":memory:", 1) == buildDSN(":memory:", 2) {
		t.Fatal("уникальность :memory: нарушена")
	}
}

func TestMigrationsIdempotentAndPersistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	ctx := context.Background()

	st1 := openDSN(t, path)
	if _, err := st1.CreateUser(ctx, domain.User{
		Username: "alice", PasswordHash: "h", Role: domain.RoleAdmin, CreatedAt: fixed,
	}); err != nil {
		t.Fatal(err)
	}

	// второй Open на том же файле: повторный goose.Up — no-op, данные живы
	st2 := openDSN(t, path)
	got, err := st2.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != domain.RoleAdmin || got.CreatedAt != fixed {
		t.Fatalf("после переоткрытия: %+v", got)
	}
}

func TestUserSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)

	has, err := st.HasUsers(ctx)
	if err != nil || has {
		t.Fatalf("HasUsers на пустой БД = %v, %v", has, err)
	}

	u, err := st.CreateUser(ctx, domain.User{
		Username: "alice", PasswordHash: "bcrypt", Role: domain.RoleAdmin, TokenVersion: 1, CreatedAt: fixed,
	})
	if err != nil || u.ID == 0 {
		t.Fatalf("CreateUser = %+v, %v", u, err)
	}

	_, err = st.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "x", CreatedAt: fixed})
	wantConflict(t, err)

	got, err := st.User(ctx, u.ID)
	if err != nil || got.Username != "alice" || got.Role != domain.RoleAdmin {
		t.Fatalf("User = %+v, %v", got, err)
	}
	if got.CreatedAt != fixed {
		t.Fatalf("CreatedAt: %v, хочу %v", got.CreatedAt, fixed)
	}

	if _, err := st.UserByUsername(ctx, "bob"); err != nil {
		wantNotFound(t, err)
	} else {
		t.Fatal("UserByUsername(bob) не вернул ошибку")
	}
	_, err = st.User(ctx, 999)
	wantNotFound(t, err)

	got.TokenVersion = 2
	if err := st.UpdateUser(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.User(ctx, u.ID)
	if got2.TokenVersion != 2 {
		t.Fatalf("UpdateUser не применился: %+v", got2)
	}

	// переименование в занятое имя — конфликт
	bob, _ := st.CreateUser(ctx, domain.User{Username: "bob", PasswordHash: "x", CreatedAt: fixed})
	got2.Username = "bob"
	wantConflict(t, st.UpdateUser(ctx, got2))

	err = st.UpdateUser(ctx, domain.User{ID: 999, Username: "ghost"})
	wantNotFound(t, err)

	all, err := st.Users(ctx)
	if err != nil || len(all) != 2 || all[0].ID > all[1].ID {
		t.Fatalf("Users = %+v, %v", all, err)
	}

	if err := st.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	err = st.DeleteUser(ctx, bob.ID)
	wantNotFound(t, err)

	has, err = st.HasUsers(ctx)
	if err != nil || !has {
		t.Fatalf("HasUsers = %v, %v", has, err)
	}
}

func TestTokenSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	u, _ := st.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "h", CreatedAt: fixed})

	tok, err := st.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Name: "ci", Prefix: "khrz_abc",
		SHA256: domain.HashToken("secret"), Scopes: []domain.Scope{domain.ScopeAdmin},
		CreatedAt: fixed,
	})
	if err != nil || tok.ID == 0 {
		t.Fatalf("CreateToken = %+v, %v", tok, err)
	}

	// уникальность хеша и префикса
	_, err = st.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Prefix: "khrz_xyz", SHA256: domain.HashToken("secret"), Scopes: nil, CreatedAt: fixed,
	})
	wantConflict(t, err)
	_, err = st.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Prefix: "khrz_abc", SHA256: domain.HashToken("other"), Scopes: nil, CreatedAt: fixed,
	})
	wantConflict(t, err)

	// FK: токен несуществующего пользователя
	_, err = st.CreateToken(ctx, domain.APIToken{
		UserID: 999, Prefix: "khrz_g", SHA256: domain.HashToken("g"), CreatedAt: fixed,
	})
	wantConflict(t, err)

	got, err := st.TokenBySHA256(ctx, domain.HashToken("secret"))
	if err != nil || got.Name != "ci" || len(got.Scopes) != 1 || got.Scopes[0] != domain.ScopeAdmin {
		t.Fatalf("TokenBySHA256 = %+v, %v", got, err)
	}
	if got.ExpiresAt != (time.Time{}) {
		t.Fatalf("ExpiresAt бессрочного токена: %v", got.ExpiresAt)
	}
	if _, err := st.TokenBySHA256(ctx, domain.HashToken("nope")); err != nil {
		wantNotFound(t, err)
	} else {
		t.Fatal("TokenBySHA256(nope) без ошибки")
	}

	// бессрочный expires_at IS NULL, срочный — эпоха
	_, err = st.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Prefix: "khrz_exp", SHA256: domain.HashToken("exp"),
		Scopes:    []domain.Scope{domain.Scope("repo:7:write")},
		CreatedAt: fixed, ExpiresAt: fixed.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := st.TokenBySHA256(ctx, domain.HashToken("exp"))
	if !exp.ExpiresAt.Equal(fixed.Add(24 * time.Hour)) {
		t.Fatalf("ExpiresAt = %v", exp.ExpiresAt)
	}
	if len(exp.Scopes) != 1 || exp.Scopes[0] != domain.Scope("repo:7:write") {
		t.Fatalf("scopes = %v", exp.Scopes)
	}

	used := fixed.Add(time.Minute)
	if err := st.TouchToken(ctx, got.ID, used); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchToken(ctx, 999, used); err != nil {
		t.Fatalf("TouchToken отсутствующего токена: %v (молчаливое отсутствие — не ошибка)", err)
	}

	list, err := st.TokensByUser(ctx, u.ID)
	if err != nil || len(list) != 2 || list[0].ID > list[1].ID {
		t.Fatalf("TokensByUser = %d токенов, %v", len(list), err)
	}

	if err := st.DeleteToken(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	err = st.DeleteToken(ctx, tok.ID)
	wantNotFound(t, err)
}

func TestRepoSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	owner, _ := st.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "h", CreatedAt: fixed})
	other, _ := st.CreateUser(ctx, domain.User{Username: "bob", PasswordHash: "h", CreatedAt: fixed})

	r, err := st.CreateRepo(ctx, domain.Repo{
		Name: "myrepo", OwnerID: owner.ID, Ecosystem: "apt",
		Quota: domain.Quota{MaxBytes: 1 << 30, MaxObjects: 100}, CreatedAt: fixed,
	})
	if err != nil || r.ID == 0 {
		t.Fatalf("CreateRepo = %+v, %v", r, err)
	}

	_, err = st.CreateRepo(ctx, domain.Repo{Name: "myrepo", OwnerID: owner.ID, CreatedAt: fixed})
	wantConflict(t, err)
	_, err = st.CreateRepo(ctx, domain.Repo{Name: "orphan", OwnerID: 999, CreatedAt: fixed})
	wantConflict(t, err)

	got, err := st.Repo(ctx, r.ID)
	if err != nil || got.Name != "myrepo" || got.Quota.MaxBytes != 1<<30 || got.Quota.MaxObjects != 100 {
		t.Fatalf("Repo = %+v, %v", got, err)
	}
	_, err = st.Repo(ctx, 999)
	wantNotFound(t, err)

	got.Quota.MaxBytes = 2 << 30
	if err := st.UpdateRepo(ctx, got); err != nil {
		t.Fatal(err)
	}
	err = st.UpdateRepo(ctx, domain.Repo{ID: 999, Name: "ghost"})
	wantNotFound(t, err)

	if err := st.Grant(ctx, domain.Perm{RepoID: r.ID, UserID: other.ID, CreatedAt: fixed}); err != nil {
		t.Fatal(err)
	}
	err = st.Grant(ctx, domain.Perm{RepoID: r.ID, UserID: other.ID, CreatedAt: fixed})
	wantConflict(t, err)

	perms, err := st.Perms(ctx, r.ID)
	if err != nil || len(perms) != 1 || perms[0].UserID != other.ID {
		t.Fatalf("Perms = %+v, %v", perms, err)
	}

	if err := st.Revoke(ctx, r.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	err = st.Revoke(ctx, r.ID, other.ID)
	wantNotFound(t, err)

	all, err := st.Repos(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("Repos = %+v, %v", all, err)
	}

	if err := st.DeleteRepo(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	err = st.DeleteRepo(ctx, r.ID)
	wantNotFound(t, err)
}

func TestRemoteSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)

	rm, err := st.CreateRemote(ctx, domain.Remote{
		Name: "deb-main", Ecosystem: "apt", BaseURL: "https://deb.example.org/debian",
		Mode: domain.ModeProxy, Enabled: true, CreatedAt: fixed,
	})
	if err != nil || rm.ID == 0 {
		t.Fatalf("CreateRemote = %+v, %v", rm, err)
	}

	_, err = st.CreateRemote(ctx, domain.Remote{Name: "deb-main", CreatedAt: fixed})
	wantConflict(t, err)

	got, err := st.Remote(ctx, rm.ID)
	if err != nil || got.BaseURL != "https://deb.example.org/debian" || got.Mode != domain.ModeProxy || !got.Enabled {
		t.Fatalf("Remote = %+v, %v", got, err)
	}
	_, err = st.Remote(ctx, 999)
	wantNotFound(t, err)

	got.Enabled = false
	got.Mode = domain.ModeMirror
	if err := st.UpdateRemote(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.Remote(ctx, rm.ID)
	if got2.Enabled || got2.Mode != domain.ModeMirror {
		t.Fatalf("UpdateRemote не применился: %+v", got2)
	}
	err = st.UpdateRemote(ctx, domain.Remote{ID: 999, Name: "ghost"})
	wantNotFound(t, err)

	if _, err := st.Remotes(ctx); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteRemote(ctx, rm.ID); err != nil {
		t.Fatal(err)
	}
	err = st.DeleteRemote(ctx, rm.ID)
	wantNotFound(t, err)
}

func TestJobSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	rm, _ := st.CreateRemote(ctx, domain.Remote{
		Name: "mirror", Ecosystem: "apt", BaseURL: "https://up.example", Mode: domain.ModeMirror, CreatedAt: fixed,
	})

	j, err := st.CreateJob(ctx, domain.SyncJob{
		RemoteID: rm.ID, State: domain.StatePending,
		Interval: time.Hour, UpdatedAt: fixed,
	})
	if err != nil || j.ID == 0 {
		t.Fatalf("CreateJob = %+v, %v", j, err)
	}

	_, err = st.CreateJob(ctx, domain.SyncJob{RemoteID: 999, UpdatedAt: fixed})
	wantConflict(t, err)

	got, err := st.Job(ctx, j.ID)
	if err != nil || got.State != domain.StatePending || got.Interval != time.Hour || got.LastRunAt != (time.Time{}) {
		t.Fatalf("Job = %+v, %v", got, err)
	}
	_, err = st.Job(ctx, 999)
	wantNotFound(t, err)

	got.State = domain.StateRunning
	got.LastRunAt = fixed
	got.Cursor = "etag:abc"
	got.Interval = 30 * time.Minute
	if err := st.UpdateJob(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.Job(ctx, j.ID)
	if got2.State != domain.StateRunning || got2.Cursor != "etag:abc" ||
		got2.Interval != 30*time.Minute || !got2.LastRunAt.Equal(fixed) {
		t.Fatalf("UpdateJob не применился: %+v", got2)
	}
	err = st.UpdateJob(ctx, domain.SyncJob{ID: 999})
	wantNotFound(t, err)

	if js, err := st.Jobs(ctx); err != nil || len(js) != 1 {
		t.Fatalf("Jobs = %+v, %v", js, err)
	}

	if err := st.DeleteJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	err = st.DeleteJob(ctx, j.ID)
	wantNotFound(t, err)
}

func TestAuditSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)

	for i := 0; i < 5; i++ {
		err := st.Record(ctx, domain.AuditEntry{
			At:    fixed.Add(time.Duration(i) * time.Minute),
			Actor: "alice", Action: "test.op", Object: fmt.Sprintf("obj:%d", i),
			Result: domain.AuditOK, Detail: `{"i":` + fmt.Sprint(i) + `}`,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	page, err := st.AuditEntries(ctx, 0, 2)
	if err != nil || len(page) != 2 || page[0].ID >= page[1].ID || page[0].Object != "obj:0" {
		t.Fatalf("страница 1 = %+v, %v", page, err)
	}
	if !page[0].At.Equal(fixed) {
		t.Fatalf("At = %v, хочу %v", page[0].At, fixed)
	}

	page, err = st.AuditEntries(ctx, page[1].ID, 2)
	if err != nil || len(page) != 2 || page[0].Object != "obj:2" {
		t.Fatalf("страница 2 = %+v, %v", page, err)
	}

	// limit <= 0 — дефолт адаптера
	all, err := st.AuditEntries(ctx, 0, 0)
	if err != nil || len(all) != 5 {
		t.Fatalf("дефолт-страница = %d записей, %v", len(all), err)
	}
	tail, err := st.AuditEntries(ctx, 4, 10)
	if err != nil || len(tail) != 1 || tail[0].Object != "obj:4" {
		t.Fatalf("хвост = %+v, %v", tail, err)
	}
}

func TestObjectIndexSuite(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)

	m := domain.ObjectMeta{
		Key: "cache/apt/1/dists/stable/Release", Size: 1234, ETag: `"v1"`,
		ContentType: "text/plain", LastModified: fixed, ExpiresAt: fixed.Add(5 * time.Minute),
	}
	if err := st.PutObjectMeta(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := st.ObjectMeta(ctx, m.Key)
	if err != nil || got.ETag != `"v1"` || got.Size != 1234 || got.ContentType != "text/plain" ||
		!got.LastModified.Equal(fixed) || !got.ExpiresAt.Equal(fixed.Add(5*time.Minute)) {
		t.Fatalf("ObjectMeta = %+v, %v", got, err)
	}

	// upsert: перезапись по тому же ключу
	m.ETag = `"v2"`
	m.Size = 99
	m.ExpiresAt = time.Time{} // бессрочный → NULL → нулевое время
	if err := st.PutObjectMeta(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ObjectMeta(ctx, m.Key)
	if got.ETag != `"v2"` || got.Size != 99 || got.ExpiresAt != (time.Time{}) {
		t.Fatalf("upsert = %+v", got)
	}

	if err := st.DeleteObjectMeta(ctx, m.Key); err != nil {
		t.Fatal(err)
	}
	// идемпотентность удаления
	if err := st.DeleteObjectMeta(ctx, m.Key); err != nil {
		t.Fatalf("повторное удаление: %v", err)
	}
	_, err = st.ObjectMeta(ctx, m.Key)
	wantNotFound(t, err)
}

func TestMemoryDSNVariants(t *testing.T) {
	ctx := context.Background()

	t.Run("двоеточие-память", func(t *testing.T) {
		st := openDSN(t, ":memory:")
		u, err := st.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "h", CreatedAt: fixed})
		if err != nil {
			t.Fatal(err)
		}
		readBack(ctx, t, st, u.ID)
	})

	t.Run("shared-cache-память", func(t *testing.T) {
		st := openDSN(t, "file:khrz-test-shared?mode=memory&cache=shared")
		u, err := st.CreateUser(ctx, domain.User{Username: "bob", PasswordHash: "h", CreatedAt: fixed})
		if err != nil {
			t.Fatal(err)
		}
		readBack(ctx, t, st, u.ID)
	})
}

// readBack — пул из 8 соединений: параллельные чтения через разные
// соединения обязаны видеть одну и ту же БД (cache=shared).
func readBack(ctx context.Context, t *testing.T, st *Store, id int64) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, err := st.User(ctx, id)
			if err != nil {
				errs <- err
				return
			}
			if u.Username == "" {
				errs <- fmt.Errorf("пустое имя пользователя из параллельного чтения")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestForeignKeysEnabled(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	// FK-прагма применяется на каждом соединении: репозиторий на
	// несуществующего владельца отклоняется БД, а не молчит
	_, err := st.CreateRepo(ctx, domain.Repo{Name: "orphan", OwnerID: 999, CreatedAt: fixed})
	var cf *domain.ConflictError
	if !errors.As(err, &cf) {
		t.Fatalf("хочу ConflictError (FK), получено: %v", err)
	}
}
