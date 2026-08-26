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

// Package contract — общие контрактные suite портов каталога и
// хранилища. Не build-tag'ится: тот же код гоняет адаптеры и в unit
// (sqlite, fs — без внешних сервисов), и в integration (postgres,
// mariadb, s3 — через CI-сервисы). Хранится НЕ в test/integration,
// чтобы unit-покрытие sqlite/fs не проседало (suite импортируется
// их _test.go, и CRUD-методы считаются в покрытии пакета-адаптера).
package contract

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// fixed — детерминированное время записи (эпоха теряет доли секунды —
// сравнение после Unix()-нормализации).
var fixed = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// Catalog — набор срезов порта каталога для контрактного suite.
// Close — опциональная очистка адаптера (закрытие *sql.DB); nil ок.
type Catalog struct {
	Users    port.UserStore
	Tokens   port.TokenStore
	Repos    port.RepoStore
	Remotes  port.RemoteStore
	Jobs     port.JobStore
	Audit    port.AuditLog
	ObjIndex port.ObjectIndex
	Close    func() error
}

// CatalogSuite гоняет контрактный suite каталога (сессия 04 + новые
// кейсы сессии 17: конкурентный upsert, keyset-пагинация на 100+
// записей) по одному адаптеру. open возвращает свежий набор на каждый
// вызов — изоляция под-тестов (чистая БД/каталог).
func CatalogSuite(t *testing.T, open func(t *testing.T) Catalog) {
	t.Helper()
	newCat := func(t *testing.T) Catalog {
		c := open(t)
		if c.Close != nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		return c
	}
	t.Run("users", func(t *testing.T) { userSuite(t, newCat(t)) })
	t.Run("tokens", func(t *testing.T) { tokenSuite(t, newCat(t)) })
	t.Run("repos", func(t *testing.T) { repoSuite(t, newCat(t)) })
	t.Run("remotes", func(t *testing.T) { remoteSuite(t, newCat(t)) })
	t.Run("jobs", func(t *testing.T) { jobSuite(t, newCat(t)) })
	t.Run("audit", func(t *testing.T) { auditSuite(t, newCat(t)) })
	t.Run("object_index", func(t *testing.T) { objectIndexSuite(t, newCat(t)) })
	t.Run("concurrent_upsert", func(t *testing.T) { concurrentUpsertSuite(t, newCat(t)) })
	t.Run("keyset_pagination_100", func(t *testing.T) { keysetPaginationSuite(t, newCat(t)) })
}

func userSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	has, err := c.Users.HasUsers(ctx)
	if err != nil || has {
		t.Fatalf("HasUsers на пустой БД = %v, %v", has, err)
	}
	u, err := c.Users.CreateUser(ctx, domain.User{
		Username: "alice", PasswordHash: "bcrypt", Role: domain.RoleAdmin, TokenVersion: 1, CreatedAt: fixed,
	})
	if err != nil || u.ID == 0 {
		t.Fatalf("CreateUser = %+v, %v", u, err)
	}
	_, err = c.Users.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "x", CreatedAt: fixed})
	wantConflict(t, err)
	got, err := c.Users.User(ctx, u.ID)
	if err != nil || got.Username != "alice" || got.Role != domain.RoleAdmin {
		t.Fatalf("User = %+v, %v", got, err)
	}
	if got.CreatedAt != fixed {
		t.Fatalf("CreatedAt: %v, хочу %v", got.CreatedAt, fixed)
	}
	if _, err := c.Users.UserByUsername(ctx, "bob"); err != nil {
		wantNotFound(t, err)
	} else {
		t.Fatal("UserByUsername(bob) не вернул ошибку")
	}
	_, err = c.Users.User(ctx, 999)
	wantNotFound(t, err)
	got.TokenVersion = 2
	if err := c.Users.UpdateUser(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, _ := c.Users.User(ctx, u.ID)
	if got2.TokenVersion != 2 {
		t.Fatalf("UpdateUser не применился: %+v", got2)
	}
	bob, _ := c.Users.CreateUser(ctx, domain.User{Username: "bob", PasswordHash: "x", CreatedAt: fixed})
	got2.Username = "bob"
	wantConflict(t, c.Users.UpdateUser(ctx, got2))
	wantNotFound(t, c.Users.UpdateUser(ctx, domain.User{ID: 999, Username: "ghost"}))
	all, err := c.Users.Users(ctx)
	if err != nil || len(all) != 2 || all[0].ID > all[1].ID {
		t.Fatalf("Users = %+v, %v", all, err)
	}
	if err := c.Users.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, c.Users.DeleteUser(ctx, bob.ID))
	has, err = c.Users.HasUsers(ctx)
	if err != nil || !has {
		t.Fatalf("HasUsers = %v, %v", has, err)
	}
}

func tokenSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	u, _ := c.Users.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "h", CreatedAt: fixed})
	tok, err := c.Tokens.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Name: "ci", Prefix: "khrz_abc",
		SHA256: domain.HashToken("secret"), Scopes: []domain.Scope{domain.ScopeAdmin},
		CreatedAt: fixed,
	})
	if err != nil || tok.ID == 0 {
		t.Fatalf("CreateToken = %+v, %v", tok, err)
	}
	_, err = c.Tokens.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Prefix: "khrz_xyz", SHA256: domain.HashToken("secret"), CreatedAt: fixed,
	})
	wantConflict(t, err)
	_, err = c.Tokens.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Prefix: "khrz_abc", SHA256: domain.HashToken("other"), CreatedAt: fixed,
	})
	wantConflict(t, err)
	_, err = c.Tokens.CreateToken(ctx, domain.APIToken{
		UserID: 999, Prefix: "khrz_g", SHA256: domain.HashToken("g"), CreatedAt: fixed,
	})
	wantConflict(t, err)
	got, err := c.Tokens.TokenBySHA256(ctx, domain.HashToken("secret"))
	if err != nil || got.Name != "ci" || len(got.Scopes) != 1 || got.Scopes[0] != domain.ScopeAdmin {
		t.Fatalf("TokenBySHA256 = %+v, %v", got, err)
	}
	if got.ExpiresAt != (time.Time{}) {
		t.Fatalf("ExpiresAt бессрочного токена: %v", got.ExpiresAt)
	}
	if _, err := c.Tokens.TokenBySHA256(ctx, domain.HashToken("nope")); err != nil {
		wantNotFound(t, err)
	} else {
		t.Fatal("TokenBySHA256(nope) без ошибки")
	}
	_, err = c.Tokens.CreateToken(ctx, domain.APIToken{
		UserID: u.ID, Prefix: "khrz_exp", SHA256: domain.HashToken("exp"),
		Scopes:    []domain.Scope{domain.Scope("repo:7:write")},
		CreatedAt: fixed, ExpiresAt: fixed.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := c.Tokens.TokenBySHA256(ctx, domain.HashToken("exp"))
	if !exp.ExpiresAt.Equal(fixed.Add(24 * time.Hour)) {
		t.Fatalf("ExpiresAt = %v", exp.ExpiresAt)
	}
	used := fixed.Add(time.Minute)
	if err := c.Tokens.TouchToken(ctx, got.ID, used); err != nil {
		t.Fatal(err)
	}
	if err := c.Tokens.TouchToken(ctx, 999, used); err != nil {
		t.Fatalf("TouchToken отсутствующего токена: %v (молчаливое отсутствие — не ошибка)", err)
	}
	list, err := c.Tokens.TokensByUser(ctx, u.ID)
	if err != nil || len(list) != 2 || list[0].ID > list[1].ID {
		t.Fatalf("TokensByUser = %d токенов, %v", len(list), err)
	}
	if err := c.Tokens.DeleteToken(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, c.Tokens.DeleteToken(ctx, tok.ID))
}

func repoSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	owner, _ := c.Users.CreateUser(ctx, domain.User{Username: "alice", PasswordHash: "h", CreatedAt: fixed})
	other, _ := c.Users.CreateUser(ctx, domain.User{Username: "bob", PasswordHash: "h", CreatedAt: fixed})
	r, err := c.Repos.CreateRepo(ctx, domain.Repo{
		Name: "myrepo", OwnerID: owner.ID, Ecosystem: "apt",
		Quota: domain.Quota{MaxBytes: 1 << 30, MaxObjects: 100}, CreatedAt: fixed,
	})
	if err != nil || r.ID == 0 {
		t.Fatalf("CreateRepo = %+v, %v", r, err)
	}
	_, err = c.Repos.CreateRepo(ctx, domain.Repo{Name: "myrepo", OwnerID: owner.ID, CreatedAt: fixed})
	wantConflict(t, err)
	_, err = c.Repos.CreateRepo(ctx, domain.Repo{Name: "orphan", OwnerID: 999, CreatedAt: fixed})
	wantConflict(t, err)
	got, err := c.Repos.Repo(ctx, r.ID)
	if err != nil || got.Name != "myrepo" || got.Quota.MaxBytes != 1<<30 || got.Quota.MaxObjects != 100 {
		t.Fatalf("Repo = %+v, %v", got, err)
	}
	_, err = c.Repos.Repo(ctx, 999)
	wantNotFound(t, err)
	got.Quota.MaxBytes = 2 << 30
	if err := c.Repos.UpdateRepo(ctx, got); err != nil {
		t.Fatal(err)
	}
	err = c.Repos.UpdateRepo(ctx, domain.Repo{ID: 999, Name: "ghost"})
	wantNotFound(t, err)
	if err := c.Repos.Grant(ctx, domain.Perm{RepoID: r.ID, UserID: other.ID, CreatedAt: fixed}); err != nil {
		t.Fatal(err)
	}
	wantConflict(t, c.Repos.Grant(ctx, domain.Perm{RepoID: r.ID, UserID: other.ID, CreatedAt: fixed}))
	perms, err := c.Repos.Perms(ctx, r.ID)
	if err != nil || len(perms) != 1 || perms[0].UserID != other.ID {
		t.Fatalf("Perms = %+v, %v", perms, err)
	}
	if err := c.Repos.Revoke(ctx, r.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, c.Repos.Revoke(ctx, r.ID, other.ID))
	all, err := c.Repos.Repos(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("Repos = %+v, %v", all, err)
	}
	if err := c.Repos.DeleteRepo(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, c.Repos.DeleteRepo(ctx, r.ID))
}

func remoteSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	rm, err := c.Remotes.CreateRemote(ctx, domain.Remote{
		Name: "deb-main", Ecosystem: "apt", BaseURL: "https://deb.example.org/debian",
		Mode: domain.ModeProxy, Enabled: true, SyncInterval: 6 * time.Hour,
		Include: []string{"stable", "stable/main"}, CreatedAt: fixed,
	})
	if err != nil || rm.ID == 0 {
		t.Fatalf("CreateRemote = %+v, %v", rm, err)
	}
	_, err = c.Remotes.CreateRemote(ctx, domain.Remote{Name: "deb-main", CreatedAt: fixed})
	wantConflict(t, err)
	got, err := c.Remotes.Remote(ctx, rm.ID)
	if err != nil || got.BaseURL != "https://deb.example.org/debian" || got.Mode != domain.ModeProxy || !got.Enabled {
		t.Fatalf("Remote = %+v, %v", got, err)
	}
	if got.SyncInterval != 6*time.Hour {
		t.Errorf("SyncInterval = %v, хочу 6h", got.SyncInterval)
	}
	if len(got.Include) != 2 || got.Include[0] != "stable" || got.Include[1] != "stable/main" {
		t.Errorf("Include = %+v", got.Include)
	}
	_, err = c.Remotes.Remote(ctx, 999)
	wantNotFound(t, err)
	got.Enabled = false
	got.Mode = domain.ModeMirror
	got.SyncInterval = 0
	got.Include = nil
	if err := c.Remotes.UpdateRemote(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, _ := c.Remotes.Remote(ctx, rm.ID)
	if got2.Enabled || got2.Mode != domain.ModeMirror {
		t.Fatalf("UpdateRemote не применился: %+v", got2)
	}
	if got2.SyncInterval != 0 {
		t.Errorf("SyncInterval после сброса = %v", got2.SyncInterval)
	}
	if got2.Include != nil {
		t.Errorf("Include после сброса = %+v", got2.Include)
	}
	err = c.Remotes.UpdateRemote(ctx, domain.Remote{ID: 999, Name: "ghost"})
	wantNotFound(t, err)
	if _, err := c.Remotes.Remotes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Remotes.DeleteRemote(ctx, rm.ID); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, c.Remotes.DeleteRemote(ctx, rm.ID))
}

func jobSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	rm, _ := c.Remotes.CreateRemote(ctx, domain.Remote{
		Name: "mirror", Ecosystem: "apt", BaseURL: "https://up.example", Mode: domain.ModeMirror, CreatedAt: fixed,
	})
	j, err := c.Jobs.CreateJob(ctx, domain.SyncJob{
		RemoteID: rm.ID, State: domain.StatePending,
		Interval: time.Hour, UpdatedAt: fixed,
	})
	if err != nil || j.ID == 0 {
		t.Fatalf("CreateJob = %+v, %v", j, err)
	}
	_, err = c.Jobs.CreateJob(ctx, domain.SyncJob{RemoteID: 999, UpdatedAt: fixed})
	wantConflict(t, err)
	got, err := c.Jobs.Job(ctx, j.ID)
	if err != nil || got.State != domain.StatePending || got.Interval != time.Hour || got.LastRunAt != (time.Time{}) {
		t.Fatalf("Job = %+v, %v", got, err)
	}
	_, err = c.Jobs.Job(ctx, 999)
	wantNotFound(t, err)
	got.State = domain.StateRunning
	got.LastRunAt = fixed
	got.Cursor = "etag:abc"
	got.Interval = 30 * time.Minute
	if err := c.Jobs.UpdateJob(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, _ := c.Jobs.Job(ctx, j.ID)
	if got2.State != domain.StateRunning || got2.Cursor != "etag:abc" ||
		got2.Interval != 30*time.Minute || !got2.LastRunAt.Equal(fixed) {
		t.Fatalf("UpdateJob не применился: %+v", got2)
	}
	err = c.Jobs.UpdateJob(ctx, domain.SyncJob{ID: 999})
	wantNotFound(t, err)
	if js, err := c.Jobs.Jobs(ctx); err != nil || len(js) != 1 {
		t.Fatalf("Jobs = %+v, %v", js, err)
	}
	if err := c.Jobs.DeleteJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, c.Jobs.DeleteJob(ctx, j.ID))
}

func auditSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		err := c.Audit.Record(ctx, domain.AuditEntry{
			At:    fixed.Add(time.Duration(i) * time.Minute),
			Actor: "alice", Action: "test.op", Object: fmt.Sprintf("obj:%d", i),
			Result: domain.AuditOK, Detail: `{"i":` + fmt.Sprint(i) + `}`,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := c.Audit.AuditEntries(ctx, 0, 2)
	if err != nil || len(page) != 2 || page[0].ID >= page[1].ID || page[0].Object != "obj:0" {
		t.Fatalf("страница 1 = %+v, %v", page, err)
	}
	if !page[0].At.Equal(fixed) {
		t.Fatalf("At = %v, хочу %v", page[0].At, fixed)
	}
	page, err = c.Audit.AuditEntries(ctx, page[1].ID, 2)
	if err != nil || len(page) != 2 || page[0].Object != "obj:2" {
		t.Fatalf("страница 2 = %+v, %v", page, err)
	}
	all, err := c.Audit.AuditEntries(ctx, 0, 0)
	if err != nil || len(all) != 5 {
		t.Fatalf("дефолт-страница = %d записей, %v", len(all), err)
	}
	tail, err := c.Audit.AuditEntries(ctx, 4, 10)
	if err != nil || len(tail) != 1 || tail[0].Object != "obj:4" {
		t.Fatalf("хвост = %+v, %v", tail, err)
	}
}

func objectIndexSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	m := domain.ObjectMeta{
		Key: "cache/apt/1/dists/stable/Release", StorageKey: "cache/apt/1/dists/stable/Release-v1a-1",
		Size: 1234, ETag: `"v1"`,
		ContentType: "text/plain", LastModified: fixed, ExpiresAt: fixed.Add(5 * time.Minute),
	}
	if err := c.ObjIndex.PutObjectMeta(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := c.ObjIndex.ObjectMeta(ctx, m.Key)
	if err != nil || got.ETag != `"v1"` || got.Size != 1234 || got.ContentType != "text/plain" ||
		got.StorageKey != m.StorageKey ||
		!got.LastModified.Equal(fixed) || !got.ExpiresAt.Equal(fixed.Add(5*time.Minute)) {
		t.Fatalf("ObjectMeta = %+v, %v", got, err)
	}
	m.ETag = `"v2"`
	m.Size = 99
	m.StorageKey = "cache/apt/1/dists/stable/Release-v2b-2"
	m.ExpiresAt = time.Time{}
	if err := c.ObjIndex.PutObjectMeta(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, _ = c.ObjIndex.ObjectMeta(ctx, m.Key)
	if got.ETag != `"v2"` || got.Size != 99 || got.StorageKey != m.StorageKey || got.ExpiresAt != (time.Time{}) {
		t.Fatalf("upsert = %+v", got)
	}
	if err := c.ObjIndex.DeleteObjectMeta(ctx, m.Key); err != nil {
		t.Fatal(err)
	}
	if err := c.ObjIndex.DeleteObjectMeta(ctx, m.Key); err != nil {
		t.Fatalf("повторное удаление: %v", err)
	}
	_, err = c.ObjIndex.ObjectMeta(ctx, m.Key)
	wantNotFound(t, err)
}

// concurrentUpsertSuite — N горутин делают upsert ObjectMeta по одному
// ключу с одинаковым значением; все обязаны завершиться без паники, а
// итоговая запись — быть валидной. -race ловит гонки адаптера.
func concurrentUpsertSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	const writers = 16
	m := domain.ObjectMeta{
		Key: "cache/rpm-md/1/repodata/primary.xml.gz", StorageKey: "",
		Size: 42, ETag: `"e"`, ContentType: "application/x-gzip",
		LastModified: fixed, ExpiresAt: fixed.Add(5 * time.Minute),
	}
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.ObjIndex.PutObjectMeta(ctx, m); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("конкурентный upsert: %v", err)
	}
	got, err := c.ObjIndex.ObjectMeta(ctx, m.Key)
	if err != nil {
		t.Fatalf("ObjectMeta после гонки: %v", err)
	}
	if got.ETag != `"e"` || got.Size != 42 {
		t.Fatalf("итоговая запись после гонки: %+v", got)
	}
}

// keysetPaginationSuite — 100+ записей аудита, пролистывание по 7:
// порядок по ID, без пропусков/дублей, продолжение корректно.
func keysetPaginationSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	const total = 120
	for i := 0; i < total; i++ {
		if err := c.Audit.Record(ctx, domain.AuditEntry{
			At:    fixed.Add(time.Duration(i) * time.Second),
			Actor: "ci", Action: "bulk.op", Object: strconv.Itoa(i), Result: domain.AuditOK, Detail: "",
		}); err != nil {
			t.Fatal(err)
		}
	}
	const limit = 7
	var seen []int64
	var afterID int64
	for {
		page, err := c.Audit.AuditEntries(ctx, afterID, limit)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			seen = append(seen, e.ID)
			if e.ID <= afterID {
				t.Fatalf("запись %d не больше afterID %d (не keyset)", e.ID, afterID)
			}
			afterID = e.ID
		}
		if len(page) < limit {
			break
		}
	}
	if len(seen) != total {
		t.Fatalf("пролистано %d записей, хочу %d", len(seen), total)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("порядок нарушен: %d после %d", seen[i], seen[i-1])
		}
	}
}

// wantNotFound/wantConflict — общие ассерты доменных ошибок.
func wantNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
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
