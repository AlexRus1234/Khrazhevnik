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

// Фейки каталога — только срезы, нужные конкретным тестам (сессия 02:
// UserStore для аутентификации, ObjectIndex для движка кеша). Прочие
// фейки дописываются по мере появления потребителей.

package testutil

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
)

// FakeUserStore — map-реализация port.UserStore: детерминированные ID
// по возрастанию, ошибки домена как у боевого адаптера БД.
type FakeUserStore struct {
	mu     sync.Mutex
	nextID int64
	byID   map[int64]domain.User
	byName map[string]int64
}

// NewFakeUserStore создаёт пустое хранилище пользователей.
func NewFakeUserStore() *FakeUserStore {
	return &FakeUserStore{byID: map[int64]domain.User{}, byName: map[string]int64{}}
}

// CreateUser записывает пользователя; нулевой ID назначается.
func (s *FakeUserStore) CreateUser(_ context.Context, u domain.User) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[u.Username]; ok {
		return domain.User{}, &domain.ConflictError{What: "пользователь", Key: u.Username}
	}
	if u.ID == 0 {
		s.nextID++
		u.ID = s.nextID
	}
	s.byID[u.ID] = u
	s.byName[u.Username] = u.ID
	return u, nil
}

// EnsureFirstUser атомарно создаёт первого пользователя; created=false —
// хранилище уже непуста (параллельный победитель).
func (s *FakeUserStore) EnsureFirstUser(_ context.Context, u domain.User) (domain.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byID) > 0 {
		return domain.User{}, false, nil
	}
	if u.ID == 0 {
		s.nextID++
		u.ID = s.nextID
	}
	s.byID[u.ID] = u
	s.byName[u.Username] = u.ID
	return u, true, nil
}

// User возвращает пользователя по ID.
func (s *FakeUserStore) User(_ context.Context, id int64) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return domain.User{}, &domain.NotFoundError{What: "пользователь", Key: strconv.FormatInt(id, 10)}
	}
	return u, nil
}

// UserByUsername возвращает пользователя по имени.
func (s *FakeUserStore) UserByUsername(_ context.Context, username string) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byName[username]
	if !ok {
		return domain.User{}, &domain.NotFoundError{What: "пользователь", Key: username}
	}
	return s.byID[id], nil
}

// Users отдаёт всех пользователей по возрастанию ID.
func (s *FakeUserStore) Users(_ context.Context) ([]domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.User, 0, len(s.byID))
	for _, u := range s.byID {
		out = append(out, u)
	}
	slices.SortFunc(out, func(a, b domain.User) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdateUser заменяет пользователя целиком.
func (s *FakeUserStore) UpdateUser(_ context.Context, u domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byID[u.ID]
	if !ok {
		return &domain.NotFoundError{What: "пользователь", Key: strconv.FormatInt(u.ID, 10)}
	}
	if other, ok := s.byName[u.Username]; ok && other != u.ID {
		return &domain.ConflictError{What: "пользователь", Key: u.Username}
	}
	delete(s.byName, old.Username)
	s.byID[u.ID] = u
	s.byName[u.Username] = u.ID
	return nil
}

// DeleteUser удаляет пользователя.
func (s *FakeUserStore) DeleteUser(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return &domain.NotFoundError{What: "пользователь", Key: strconv.FormatInt(id, 10)}
	}
	delete(s.byID, id)
	delete(s.byName, u.Username)
	return nil
}

// HasUsers сообщает, есть ли хоть один пользователь.
func (s *FakeUserStore) HasUsers(_ context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID) > 0, nil
}

// FakeObjectIndex — map-реализация port.ObjectIndex поверх ObjectMeta.
type FakeObjectIndex struct {
	mu    sync.Mutex
	byKey map[string]domain.ObjectMeta
}

// NewFakeObjectIndex создаёт пустой индекс.
func NewFakeObjectIndex() *FakeObjectIndex {
	return &FakeObjectIndex{byKey: map[string]domain.ObjectMeta{}}
}

// ObjectMeta возвращает запись индекса по ключу.
func (s *FakeObjectIndex) ObjectMeta(_ context.Context, key string) (domain.ObjectMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byKey[key]
	if !ok {
		return domain.ObjectMeta{}, &domain.NotFoundError{What: "метаданные объекта", Key: key}
	}
	return m, nil
}

// PutObjectMeta — upsert записи.
func (s *FakeObjectIndex) PutObjectMeta(_ context.Context, m domain.ObjectMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[m.Key] = m
	return nil
}

// DeleteObjectMeta идемпотентно удаляет запись.
func (s *FakeObjectIndex) DeleteObjectMeta(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byKey, key)
	return nil
}

// FakeAuditLog — slice-реализация port.AuditLog: записи по возрастанию
// ID (как у боевого адаптера БД), keyset-пагинация AuditEntries.
// Нужен тестам админ-API и audit-middleware (сессия 09).
type FakeAuditLog struct {
	mu      sync.Mutex
	nextID  int64
	entries []domain.AuditEntry
}

// NewFakeAuditLog создаёт пустой аудит-лог.
func NewFakeAuditLog() *FakeAuditLog { return &FakeAuditLog{} }

// Record добавляет запись; ID назначается по возрастанию.
func (s *FakeAuditLog) Record(_ context.Context, e domain.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	e.ID = s.nextID
	if e.At.IsZero() {
		e.At = time.Unix(0, 0).UTC()
	}
	s.entries = append(s.entries, e)
	return nil
}

// AuditEntries — страница записей с ID строго больше afterID по
// возрастанию ID; limit <= 0 — разумный дефолт (как у боевого адаптера).
func (s *FakeAuditLog) AuditEntries(_ context.Context, afterID int64, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.AuditEntry
	for _, e := range s.entries {
		if e.ID <= afterID {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Len возвращает число записей (для проверок в тестах).
func (s *FakeAuditLog) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// FakeRevocations — map-реализация port.SessionRevocationStore: как
// боевой адаптер, при вставке чистит записи, просроченные к now.
// Нужен тестам аутентификации (сессия 25).
type FakeRevocations struct {
	mu   sync.Mutex
	jtis map[string]time.Time
}

// NewFakeRevocations создаёт пустое хранилище отзывов.
func NewFakeRevocations() *FakeRevocations {
	return &FakeRevocations{jtis: map[string]time.Time{}}
}

// InsertRevocation отзывает jti до expiresAt; попутно чистит записи,
// просроченные к now (паритет с боевым адаптером).
func (s *FakeRevocations) InsertRevocation(_ context.Context, jti string, now, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for j, exp := range s.jtis {
		if exp.Before(now) {
			delete(s.jtis, j)
		}
	}
	s.jtis[jti] = expiresAt
	return nil
}

// IsRevoked сообщает, жив ли отзыв jti на момент now.
func (s *FakeRevocations) IsRevoked(_ context.Context, jti string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.jtis[jti]
	return ok && !exp.Before(now), nil
}

// Len возвращает число записей (для проверок в тестах).
func (s *FakeRevocations) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jtis)
}

// FakeRepoStore — map-реализация port.RepoStore: детерминированные ID
// по возрастанию, ошибки домена как у боевого адаптера БД. Нужен тестам
// publish-движка (сессия 14); здесь — для полноты срезов каталога.
type FakeRepoStore struct {
	mu     sync.Mutex
	nextID int64
	byID   map[int64]domain.Repo
	byName map[string]int64
	perms  map[int64][]domain.Perm
}

// NewFakeRepoStore создаёт пустое хранилище репозиториев.
func NewFakeRepoStore() *FakeRepoStore {
	return &FakeRepoStore{byID: map[int64]domain.Repo{}, byName: map[string]int64{}, perms: map[int64][]domain.Perm{}}
}

// CreateRepo записывает репозиторий; нулевой ID назначается.
func (s *FakeRepoStore) CreateRepo(_ context.Context, r domain.Repo) (domain.Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[r.Name]; ok {
		return domain.Repo{}, &domain.ConflictError{What: "репозиторий", Key: r.Name}
	}
	if r.ID == 0 {
		s.nextID++
		r.ID = s.nextID
	}
	s.byID[r.ID] = r
	s.byName[r.Name] = r.ID
	return r, nil
}

// Repo возвращает репозиторий по ID.
func (s *FakeRepoStore) Repo(_ context.Context, id int64) (domain.Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return domain.Repo{}, &domain.NotFoundError{What: "репозиторий", Key: strconv.FormatInt(id, 10)}
	}
	return r, nil
}

// RepoByName возвращает репозиторий по имени (для публичного роутера).
func (s *FakeRepoStore) RepoByName(_ context.Context, name string) (domain.Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byName[name]
	if !ok {
		return domain.Repo{}, &domain.NotFoundError{What: "репозиторий", Key: name}
	}
	return s.byID[id], nil
}

// Repos отдаёт все репозитории по возрастанию ID.
func (s *FakeRepoStore) Repos(_ context.Context) ([]domain.Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.Repo, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b domain.Repo) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdateRepo заменяет репозиторий целиком.
func (s *FakeRepoStore) UpdateRepo(_ context.Context, r domain.Repo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byID[r.ID]
	if !ok {
		return &domain.NotFoundError{What: "репозиторий", Key: strconv.FormatInt(r.ID, 10)}
	}
	if other, ok := s.byName[r.Name]; ok && other != r.ID {
		return &domain.ConflictError{What: "репозиторий", Key: r.Name}
	}
	delete(s.byName, old.Name)
	s.byID[r.ID] = r
	s.byName[r.Name] = r.ID
	return nil
}

// DeleteRepo удаляет репозиторий.
func (s *FakeRepoStore) DeleteRepo(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return &domain.NotFoundError{What: "репозиторий", Key: strconv.FormatInt(id, 10)}
	}
	delete(s.byID, id)
	delete(s.byName, r.Name)
	delete(s.perms, id)
	return nil
}

// Grant выдаёт право записи.
func (s *FakeRepoStore) Grant(_ context.Context, p domain.Perm) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ex := range s.perms[p.RepoID] {
		if ex.UserID == p.UserID {
			return nil
		}
	}
	s.perms[p.RepoID] = append(s.perms[p.RepoID], p)
	return nil
}

// Revoke отбирает право записи.
func (s *FakeRepoStore) Revoke(_ context.Context, repoID, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := s.perms[repoID]
	for i, ex := range ps {
		if ex.UserID == userID {
			s.perms[repoID] = append(ps[:i], ps[i+1:]...)
			return nil
		}
	}
	return nil
}

// Perms отдаёт права репозитория по возрастанию userID.
func (s *FakeRepoStore) Perms(_ context.Context, repoID int64) ([]domain.Perm, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]domain.Perm(nil), s.perms[repoID]...)
	slices.SortFunc(out, func(a, b domain.Perm) int { return cmp.Compare(a.UserID, b.UserID) })
	return out, nil
}

// FakeJobStore — map-реализация port.JobStore: детерминированные ID
// по возрастанию, ошибки домена как у боевого адаптера БД. Нужен
// тестам зеркала (сессия 11); здесь — для полноты срезов каталога.
type FakeJobStore struct {
	mu     sync.Mutex
	nextID int64
	byID   map[int64]domain.SyncJob
}

// NewFakeJobStore создаёт пустое хранилище задач.
func NewFakeJobStore() *FakeJobStore { return &FakeJobStore{byID: map[int64]domain.SyncJob{}} }

// CreateJob записывает задачу; нулевой ID назначается.
func (s *FakeJobStore) CreateJob(_ context.Context, j domain.SyncJob) (domain.SyncJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j.ID == 0 {
		s.nextID++
		j.ID = s.nextID
	}
	s.byID[j.ID] = j
	return j, nil
}

// Job возвращает задачу по ID.
func (s *FakeJobStore) Job(_ context.Context, id int64) (domain.SyncJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.byID[id]
	if !ok {
		return domain.SyncJob{}, &domain.NotFoundError{What: "sync-задача", Key: strconv.FormatInt(id, 10)}
	}
	return j, nil
}

// Jobs отдаёт все задачи по возрастанию ID.
func (s *FakeJobStore) Jobs(_ context.Context) ([]domain.SyncJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.SyncJob, 0, len(s.byID))
	for _, j := range s.byID {
		out = append(out, j)
	}
	slices.SortFunc(out, func(a, b domain.SyncJob) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdateJob заменяет задачу целиком.
func (s *FakeJobStore) UpdateJob(_ context.Context, j domain.SyncJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[j.ID]; !ok {
		return &domain.NotFoundError{What: "sync-задача", Key: strconv.FormatInt(j.ID, 10)}
	}
	s.byID[j.ID] = j
	return nil
}

// DeleteJob удаляет задачу.
func (s *FakeJobStore) DeleteJob(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return &domain.NotFoundError{What: "sync-задача", Key: strconv.FormatInt(id, 10)}
	}
	delete(s.byID, id)
	return nil
}

// FakeRemoteStore — map-реализация port.RemoteStore: детерминированные
// ID по возрастанию, ошибки домена как у боевого адаптера БД. Нужен
// адаптерам экосистем (apt — сессия 07) и тестам зеркала (сессия 11).
type FakeRemoteStore struct {
	mu     sync.Mutex
	nextID int64
	byID   map[int64]domain.Remote
	byName map[string]int64
}

// NewFakeRemoteStore создаёт пустое хранилище remotes.
func NewFakeRemoteStore() *FakeRemoteStore {
	return &FakeRemoteStore{byID: map[int64]domain.Remote{}, byName: map[string]int64{}}
}

// CreateRemote записывает upstream; нулевой ID назначается.
func (s *FakeRemoteStore) CreateRemote(_ context.Context, r domain.Remote) (domain.Remote, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[r.Name]; ok {
		return domain.Remote{}, &domain.ConflictError{What: "remote", Key: r.Name}
	}
	if r.ID == 0 {
		s.nextID++
		r.ID = s.nextID
	}
	s.byID[r.ID] = r
	s.byName[r.Name] = r.ID
	return r, nil
}

// Remote возвращает upstream по ID.
func (s *FakeRemoteStore) Remote(_ context.Context, id int64) (domain.Remote, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return domain.Remote{}, &domain.NotFoundError{What: "remote", Key: strconv.FormatInt(id, 10)}
	}
	return r, nil
}

// Remotes отдаёт все upstream'ы по возрастанию ID.
func (s *FakeRemoteStore) Remotes(_ context.Context) ([]domain.Remote, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.Remote, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b domain.Remote) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdateRemote заменяет upstream целиком.
func (s *FakeRemoteStore) UpdateRemote(_ context.Context, r domain.Remote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.byID[r.ID]
	if !ok {
		return &domain.NotFoundError{What: "remote", Key: strconv.FormatInt(r.ID, 10)}
	}
	if other, ok := s.byName[r.Name]; ok && other != r.ID {
		return &domain.ConflictError{What: "remote", Key: r.Name}
	}
	delete(s.byName, old.Name)
	s.byID[r.ID] = r
	s.byName[r.Name] = r.ID
	return nil
}

// DeleteRemote удаляет upstream.
func (s *FakeRemoteStore) DeleteRemote(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return &domain.NotFoundError{What: "remote", Key: strconv.FormatInt(id, 10)}
	}
	delete(s.byID, id)
	delete(s.byName, r.Name)
	return nil
}

// FakeStatsStore — map-реализация port.StatsStore: снапшот пишется
// целиком (upsert по имени экосистемы, как у боевого адаптера БД),
// ResetStats чистит все строки. Каждая SaveStatsSnapshot записывается
// в историю — тестам флаш-цикла statskeeper (сессия 96) нужно число
// и содержимое снапшотов, а не только финальное состояние.
type FakeStatsStore struct {
	mu    sync.Mutex
	rows  map[string]domain.CacheStatsRow
	saves [][]domain.CacheStatsRow
}

// NewFakeStatsStore создаёт пустое хранилище снапшотов.
func NewFakeStatsStore() *FakeStatsStore {
	return &FakeStatsStore{rows: map[string]domain.CacheStatsRow{}}
}

// SaveStatsSnapshot перезаписывает строки переданных экосистем
// (upsert по Ecosystem), сохраняя копию снапшота в историю.
func (s *FakeStatsStore) SaveStatsSnapshot(_ context.Context, rows []domain.CacheStatsRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]domain.CacheStatsRow, len(rows))
	copy(cp, rows)
	s.saves = append(s.saves, cp)
	for _, r := range rows {
		s.rows[r.Ecosystem] = r
	}
	return nil
}

// StatsSnapshot отдаёт все строки по возрастанию имени экосистемы.
func (s *FakeStatsStore) StatsSnapshot(_ context.Context) ([]domain.CacheStatsRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.CacheStatsRow, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b domain.CacheStatsRow) int { return cmp.Compare(a.Ecosystem, b.Ecosystem) })
	return out, nil
}

// ResetStats удаляет все строки (история снапшотов не трогается).
func (s *FakeStatsStore) ResetStats(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = map[string]domain.CacheStatsRow{}
	return nil
}

// Saves возвращает копию истории снапшотов (для проверок числа
// и последовательности флашей).
func (s *FakeStatsStore) Saves() [][]domain.CacheStatsRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]domain.CacheStatsRow, len(s.saves))
	for i, sv := range s.saves {
		out[i] = append([]domain.CacheStatsRow(nil), sv...)
	}
	return out
}
