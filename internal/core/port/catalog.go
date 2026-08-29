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

// Порт каталога — персистентные сущности (БД). Interface Segregation:
// маленькие интерфейсы реализуются одним адаптером БД (mod/db/*),
// но тестовые фейки пишутся только под нужный срез. Никаких
// orm/struct-тегов: порты говорят моделями domain.

package port

import (
	"context"
	"time"

	"khrazhevnik/internal/core/domain"
)

// UserStore — учётные записи админки. Ошибки: отсутствующий
// пользователь — *domain.NotFoundError, занятое имя —
// *domain.ConflictError.
type UserStore interface {
	CreateUser(ctx context.Context, u domain.User) (domain.User, error)
	// EnsureFirstUser атомарно создаёт пользователя только на пустой
	// таблице (один стейтмент INSERT ... SELECT ... WHERE NOT EXISTS).
	// Второй результат — создан ли пользователь; параллельные вызовы в
	// bootstrap-окне завершает ровно один победитель (аудит 2026-08-27:
	// HasUsers→CreateUser — гонка на двух админов).
	EnsureFirstUser(ctx context.Context, u domain.User) (domain.User, bool, error)
	User(ctx context.Context, id int64) (domain.User, error)
	UserByUsername(ctx context.Context, username string) (domain.User, error)
	Users(ctx context.Context) ([]domain.User, error)
	UpdateUser(ctx context.Context, u domain.User) error
	DeleteUser(ctx context.Context, id int64) error
	// HasUsers — «есть ли хоть один пользователь»: защита
	// POST /api/v1/setup (первый админ создаётся только на пустой БД).
	HasUsers(ctx context.Context) (bool, error)
}

// TokenStore — scoped API-токены. Поиск авторизации — по sha256
// (токен целиком нигде не хранится).
type TokenStore interface {
	CreateToken(ctx context.Context, t domain.APIToken) (domain.APIToken, error)
	TokenBySHA256(ctx context.Context, sha256 string) (domain.APIToken, error)
	TokensByUser(ctx context.Context, userID int64) ([]domain.APIToken, error)
	DeleteToken(ctx context.Context, id int64) error
	RevokeToken(ctx context.Context, id int64, revokedAt time.Time) error
	// TouchToken фиксирует время последнего использования токена.
	TouchToken(ctx context.Context, id int64, usedAt time.Time) error
}

// RepoStore — личные репозитории и права на запись в них.
type RepoStore interface {
	CreateRepo(ctx context.Context, r domain.Repo) (domain.Repo, error)
	Repo(ctx context.Context, id int64) (domain.Repo, error)
	// RepoByName — lookup по имени для публичного роутера :29202
	// (GET /repo/<name>/<путь>); имена уникальны в таблице repos.
	RepoByName(ctx context.Context, name string) (domain.Repo, error)
	Repos(ctx context.Context) ([]domain.Repo, error)
	UpdateRepo(ctx context.Context, r domain.Repo) error
	DeleteRepo(ctx context.Context, id int64) error
	Grant(ctx context.Context, p domain.Perm) error
	Revoke(ctx context.Context, repoID, userID int64) error
	Perms(ctx context.Context, repoID int64) ([]domain.Perm, error)
}

// RemoteStore — настроенные upstream'ы (прокси/зеркала).
type RemoteStore interface {
	CreateRemote(ctx context.Context, r domain.Remote) (domain.Remote, error)
	Remote(ctx context.Context, id int64) (domain.Remote, error)
	Remotes(ctx context.Context) ([]domain.Remote, error)
	UpdateRemote(ctx context.Context, r domain.Remote) error
	DeleteRemote(ctx context.Context, id int64) error
}

// JobStore — sync-задачи зеркал: состояние и resume-курсор.
type JobStore interface {
	CreateJob(ctx context.Context, j domain.SyncJob) (domain.SyncJob, error)
	Job(ctx context.Context, id int64) (domain.SyncJob, error)
	Jobs(ctx context.Context) ([]domain.SyncJob, error)
	UpdateJob(ctx context.Context, j domain.SyncJob) error
	DeleteJob(ctx context.Context, id int64) error
}

// AuditLog — аудит мутаций. Record не должен ломать основную
// операцию: движок вызывает его после коммита и сам решает, что
// делать с ошибкой записи.
type AuditLog interface {
	Record(ctx context.Context, e domain.AuditEntry) error
	// AuditEntries — страница записей с ID строго больше afterID,
	// по возрастанию ID; limit <= 0 — разумный дефолт адаптера.
	AuditEntries(ctx context.Context, afterID int64, limit int) ([]domain.AuditEntry, error)
}

// ObjectIndex — индекс mutable-объектов кеша (etag/expires) в БД,
// отдельно от байтов в Storage. PutObjectMeta — upsert;
// DeleteObjectMeta идемпотентен (записи может уже не быть).
type ObjectIndex interface {
	ObjectMeta(ctx context.Context, key string) (domain.ObjectMeta, error)
	PutObjectMeta(ctx context.Context, m domain.ObjectMeta) error
	DeleteObjectMeta(ctx context.Context, key string) error
}

// SessionRevocationStore — персистентный отзыв JWT-сессий: logout
// переживает рестарт процесса, in-memory карта в auth.Service — только
// fast-path (аудит 2026-08-27: in-memory отзыв «оживал» после
// рестарта до естественного exp токена).
type SessionRevocationStore interface {
	// InsertRevocation отзывает jti до expiresAt и попутно чистит
	// записи, просроченные к моменту now (один вызов = вставка +
	// гигиена; logout редок — отдельный тик чистки не нужен).
	// Повторная вставка того же jti — обновление (идемпотентно).
	InsertRevocation(ctx context.Context, jti string, now, expiresAt time.Time) error
	// IsRevoked сообщает, жив ли отзыв jti на момент now.
	IsRevoked(ctx context.Context, jti string, now time.Time) (bool, error)
}
