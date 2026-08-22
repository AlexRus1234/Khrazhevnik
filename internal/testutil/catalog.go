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
