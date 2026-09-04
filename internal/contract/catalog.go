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
	"strings"
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
	Users       port.UserStore
	Tokens      port.TokenStore
	Repos       port.RepoStore
	Remotes     port.RemoteStore
	Jobs        port.JobStore
	Audit       port.AuditLog
	ObjIndex    port.ObjectIndex
	Revocations port.SessionRevocationStore
	Close       func() error
}

// CatalogSuite гоняет контрактный suite каталога (сессия 04; кейсы
// сессии 17: конкурентный upsert, keyset-пагинация на 100+ записей;
// кейсы сессии 21: no-op UPDATE, revoke roundtrip, FK-удаление,
// граница длины ключа 767, пустая страница аудита; кейсы сессии 26:
// cap limit аудита) по одному адаптеру.
// open возвращает свежий набор на каждый вызов — изоляция под-тестов
// (чистая БД/каталог).
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
	t.Run("first_user_atomic", func(t *testing.T) { firstUserAtomicSuite(t, newCat(t)) })
	t.Run("tokens", func(t *testing.T) { tokenSuite(t, newCat(t)) })
	t.Run("repos", func(t *testing.T) { repoSuite(t, newCat(t)) })
	t.Run("remotes", func(t *testing.T) { remoteSuite(t, newCat(t)) })
	t.Run("jobs", func(t *testing.T) { jobSuite(t, newCat(t)) })
	t.Run("audit", func(t *testing.T) { auditSuite(t, newCat(t)) })
	t.Run("audit_limit_cap", func(t *testing.T) { auditLimitCapSuite(t, newCat(t)) })
	t.Run("object_index", func(t *testing.T) { objectIndexSuite(t, newCat(t)) })
	t.Run("revocations", func(t *testing.T) { revocationsSuite(t, newCat(t)) })
	t.Run("noop_update", func(t *testing.T) { noopUpdateSuite(t, newCat(t)) })
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

// firstUserAtomicSuite — атомарность bootstrap первого пользователя
// (аудит 2026-08-27): 20 параллельных EnsureFirstUser на пустой таблице
// завершает ровно один победитель; таблица содержит ровно одного
// пользователя — победителя. UNIQUE(username) тут ни при чём: имена
// у писателей разные, механизм — пустота таблицы.
func firstUserAtomicSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	const writers = 20
	type outcome struct {
		username string
		created  bool
	}
	outcomes := make(chan outcome, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("racer-%02d", i)
			u, created, err := c.Users.EnsureFirstUser(ctx, domain.User{
				Username: name, PasswordHash: "h", Role: domain.RoleAdmin,
				TokenVersion: 1, CreatedAt: fixed,
			})
			if err != nil {
				t.Errorf("EnsureFirstUser(%s): %v", name, err)
				return
			}
			if created && u.ID == 0 {
				t.Errorf("EnsureFirstUser(%s): создан без ID", name)
			}
			outcomes <- outcome{username: name, created: created}
		}()
	}
	wg.Wait()
	close(outcomes)
	var winners []string
	for o := range outcomes {
		if o.created {
			winners = append(winners, o.username)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("победителей bootstrap-гонки %d, хочу ровно 1: %v", len(winners), winners)
	}
	all, err := c.Users.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Username != winners[0] {
		t.Fatalf("после гонки в таблице %+v, хочу единственного %q", all, winners[0])
	}
	// Повторный вызов на непустой таблице — created=false без ошибки.
	if _, created, err := c.Users.EnsureFirstUser(ctx, domain.User{
		Username: "late-comer", PasswordHash: "h", CreatedAt: fixed,
	}); err != nil || created {
		t.Fatalf("EnsureFirstUser на непустой таблице = created %v, err %v; хочу false, nil", created, err)
	}
}

// FirstUserBarrierSuite — барьерная форма firstUserAtomicSuite
// (сессия 69): все N писателей стартуют одновременно по close-каналу,
// максимально перекрывая окно INSERT..SELECT..WHERE NOT EXISTS.
// Обычная гонка зависит от таймингов планировщика — зелёный ничего
// не доказывает; барьер превращает спор внешнего ревью 2026-09-03
// о mariadb gap-локах в факт. Ассерт: создан ровно один админ,
// прочие — created=false без ошибки (в т.ч. без ConflictError;
// ретраи 1213/1205 не должны выходить наружу).
func FirstUserBarrierSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	const writers = 50
	start := make(chan struct{})
	type outcome struct {
		name    string
		created bool
	}
	outcomes := make(chan outcome, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("barrier-%02d", i)
			_, created, err := c.Users.EnsureFirstUser(ctx, domain.User{
				Username: name, PasswordHash: "h", Role: domain.RoleAdmin,
				TokenVersion: 1, CreatedAt: fixed,
			})
			if err != nil {
				t.Errorf("EnsureFirstUser(%s): %v (хочу created=false без ошибки)", name, err)
				return
			}
			outcomes <- outcome{name: name, created: created}
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)
	var winners []string
	for o := range outcomes {
		if o.created {
			winners = append(winners, o.name)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("победителей барьер-гонки %d, хочу ровно 1: %v", len(winners), winners)
	}
	all, err := c.Users.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Username != winners[0] {
		t.Fatalf("после барьер-гонки в таблице %d записей, хочу единственного %q", len(all), winners[0])
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
	// RevokeToken roundtrip: revoked_at виден в списке пользователя,
	// повторный revoke идемпотентен, revoke отсутствующего — NotFound.
	revoked := fixed.Add(3 * time.Minute)
	if err := c.Tokens.RevokeToken(ctx, exp.ID, revoked); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	list, err := c.Tokens.TokensByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	sawRevoked := false
	for _, tk := range list {
		if tk.ID == exp.ID {
			sawRevoked = tk.RevokedAt.Equal(revoked)
		}
	}
	if len(list) != 2 || list[0].ID > list[1].ID || !sawRevoked {
		t.Fatalf("TokensByUser после revoke = %d токентов, revoked_at отражён: %v", len(list), sawRevoked)
	}
	if err := c.Tokens.RevokeToken(ctx, exp.ID, revoked.Add(time.Minute)); err != nil {
		t.Fatalf("повторный revoke должен быть идемпотентен: %v", err)
	}
	wantNotFound(t, c.Tokens.RevokeToken(ctx, 999, revoked))
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
	// FK-удаление: владелец с репозиторием не удаляется — Conflict на
	// всех драйверах, а не сырая ошибка БД.
	wantConflict(t, c.Users.DeleteUser(ctx, owner.ID))
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
	// afterID за концом журнала: пустая страница без ошибки, а не
	// NotFound (keyset-пагинация не знает про «конец»).
	beyond, err := c.Audit.AuditEntries(ctx, tail[0].ID+1000, 10)
	if err != nil || len(beyond) != 0 {
		t.Fatalf("страница за концом = %d записей, %v (хочу пустую без ошибки)", len(beyond), err)
	}
}

// auditLimitCapSuite — client limit не протаскивается в SQL как есть:
// AuditEntries(…, 1e9) обязана вернуть страницу не больше 1000
// (верхняя граница драйверов). Число 1000 — контракт адаптеров,
// здесь зафиксировано независимо от них. 1001 запись — на одну выше
// границы, чтобы cap реально сработал, а не прошёл по недобору.
func auditLimitCapSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	const (
		capLimit  = 1000
		totalRecs = capLimit + 1
	)
	for i := 0; i < totalRecs; i++ {
		if err := c.Audit.Record(ctx, domain.AuditEntry{
			At:    fixed.Add(time.Duration(i) * time.Second),
			Actor: "ci", Action: "cap.op", Object: strconv.Itoa(i), Result: domain.AuditOK, Detail: "",
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := c.Audit.AuditEntries(ctx, 0, 1_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != capLimit {
		t.Fatalf("limit=1e9 вернул %d записей, хочу ровно %d (cap)", len(page), capLimit)
	}
	// Продолжение за cap читается следующей страницей (keyset).
	rest, err := c.Audit.AuditEntries(ctx, page[len(page)-1].ID, 1_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != totalRecs-capLimit {
		t.Fatalf("хвост после cap = %d записей, хочу %d", len(rest), totalRecs-capLimit)
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
	// Граница длины ключа: 767 байт — предел VARCHAR(767) PK mariadb
	// object_index и ровно maxKeyLen домена; проходит на всех драйверах.
	boundary := domain.ObjectMeta{
		Key:        "cache/" + strings.Repeat("k", 761), // 6 + 761 = 767 байт
		StorageKey: "cache-boundary-1", Size: 1, ETag: `"b"`,
		ContentType: "application/octet-stream", LastModified: fixed,
	}
	if err := c.ObjIndex.PutObjectMeta(ctx, boundary); err != nil {
		t.Fatalf("PutObjectMeta(ключ 767 байт): %v", err)
	}
	if _, err := c.ObjIndex.ObjectMeta(ctx, boundary.Key); err != nil {
		t.Fatalf("ObjectMeta(ключ 767 байт): %v", err)
	}
}

// revocationsSuite — персистентный отзыв JWT-сессий (сессия 25):
// вставка → проверка; после истечения срока отзыв не активен;
// повторная вставка того же jti идемпотентна. Кейс «рестарта»
// (новый адаптер на той же БД видит отзыв) — в integration.
func revocationsSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	now := fixed
	if err := c.Revocations.InsertRevocation(ctx, "jti-1", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	yes, err := c.Revocations.IsRevoked(ctx, "jti-1", now)
	if err != nil || !yes {
		t.Fatalf("IsRevoked(jti-1) = %v, %v; хочу true", yes, err)
	}
	if yes, err := c.Revocations.IsRevoked(ctx, "jti-2", now); err != nil || yes {
		t.Fatalf("IsRevoked(чужой) = %v, %v; хочу false", yes, err)
	}
	// Граница срока: ровно до expiresAt отзыв активен, после — нет.
	yes, err = c.Revocations.IsRevoked(ctx, "jti-1", now.Add(time.Hour))
	if err != nil || !yes {
		t.Fatalf("IsRevoked(в срок) = %v, %v; хочу true", yes, err)
	}
	if yes, err := c.Revocations.IsRevoked(ctx, "jti-1", now.Add(time.Hour+time.Second)); err != nil || yes {
		t.Fatalf("IsRevoked(после срока) = %v, %v; хочу false", yes, err)
	}
	// Повторная вставка — обновление срока, не ошибка.
	if err := c.Revocations.InsertRevocation(ctx, "jti-1", now, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("повторная вставка отзыва: %v", err)
	}
	if yes, err := c.Revocations.IsRevoked(ctx, "jti-1", now.Add(time.Hour+time.Second)); err != nil || !yes {
		t.Fatalf("обновлённый срок отзыва: %v, %v; хочу true", yes, err)
	}
}

// noopUpdateSuite — пересохранение тех же значений: успех, а не ложный
// NotFound. Регрессия mariadb changed-rows (сессия 21): без
// clientFoundRows no-op UPDATE отдаёт 0 затронутых строк.
func noopUpdateSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	u, err := c.Users.CreateUser(ctx, domain.User{
		Username: "alice", PasswordHash: "h", Role: domain.RoleAdmin, TokenVersion: 1, CreatedAt: fixed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("no-op UpdateUser: %v", err)
	}
	r, err := c.Repos.CreateRepo(ctx, domain.Repo{
		Name: "myrepo", OwnerID: u.ID, Ecosystem: "apt",
		Quota: domain.Quota{MaxBytes: 1 << 20, MaxObjects: 10}, CreatedAt: fixed,
	})
	if err != nil {
		t.Fatal(err)
	}
	sameRepo, err := c.Repos.Repo(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Repos.UpdateRepo(ctx, sameRepo); err != nil {
		t.Fatalf("no-op UpdateRepo: %v", err)
	}
	rm, err := c.Remotes.CreateRemote(ctx, domain.Remote{
		Name: "deb", Ecosystem: "apt", BaseURL: "https://up.example",
		Mode: domain.ModeProxy, Enabled: true, SyncInterval: time.Hour,
		Include: []string{"stable"}, CreatedAt: fixed,
	})
	if err != nil {
		t.Fatal(err)
	}
	sameRemote, err := c.Remotes.Remote(ctx, rm.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Remotes.UpdateRemote(ctx, sameRemote); err != nil {
		t.Fatalf("no-op UpdateRemote: %v", err)
	}
	j, err := c.Jobs.CreateJob(ctx, domain.SyncJob{
		RemoteID: rm.ID, State: domain.StatePending, Interval: time.Hour,
		LastRunAt: fixed, Cursor: "etag:1", UpdatedAt: fixed,
	})
	if err != nil {
		t.Fatal(err)
	}
	sameJob, err := c.Jobs.Job(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Jobs.UpdateJob(ctx, sameJob); err != nil {
		t.Fatalf("no-op UpdateJob: %v", err)
	}
}

// concurrentUpsertSuite — N горутин делают upsert ObjectMeta по одному
// ключу с РАЗНЫМИ значениями: все обязаны завершиться без паники, а
// итоговая строка — быть ровно одной из записанных версий целиком
// (последний победил), без порчи — смешения колонок разных версий.
// -race ловит гонки адаптера.
func concurrentUpsertSuite(t *testing.T, c Catalog) {
	ctx := context.Background()
	const writers = 16
	base := domain.ObjectMeta{
		Key:         "cache/rpm-md/1/repodata/primary.xml.gz",
		ContentType: "application/x-gzip", LastModified: fixed,
		ExpiresAt: fixed.Add(5 * time.Minute),
	}
	versions := make([]domain.ObjectMeta, writers)
	for i := range versions {
		v := base
		v.Size = int64(42 + i)
		v.ETag = fmt.Sprintf(`"e%d"`, i)
		v.StorageKey = fmt.Sprintf("primary-v%d", i)
		versions[i] = v
	}
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.ObjIndex.PutObjectMeta(ctx, versions[i]); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("конкурентный upsert: %v", err)
	}
	got, err := c.ObjIndex.ObjectMeta(ctx, base.Key)
	if err != nil {
		t.Fatalf("ObjectMeta после гонки: %v", err)
	}
	intact := false
	for _, v := range versions {
		if got.ETag == v.ETag && got.Size == v.Size && got.StorageKey == v.StorageKey {
			intact = true
			break
		}
	}
	if !intact {
		t.Fatalf("итоговая запись после гонки — смешение версий: %+v", got)
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
