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
