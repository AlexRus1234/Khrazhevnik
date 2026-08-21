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

// Реализации срезов порта каталога (port.UserStore, …, ObjectIndex)
// поверх одного *sql.DB. Время — эпоха Unix (dbtalk.Now), нулевое
// время домена — NULL. Ошибки БД маппятся в типизированные ошибки
// domain: UNIQUE/PK → Conflict, отсутствие строки → NotFound.

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"khrazhevnik/internal/core/dbtalk"
	"khrazhevnik/internal/core/domain"
)

// auditDefaultLimit — разумный дефолт страницы аудита (limit <= 0).
const auditDefaultLimit = 100

// Пользователи. HasUsers — защита POST /api/v1/setup.
const (
	sqlUserInsert = `INSERT INTO users (username, password_hash, role, token_version, created_at)
		VALUES (?, ?, ?, ?, ?) RETURNING id`
	sqlUserSelect = `SELECT id, username, password_hash, role, token_version, created_at FROM users`
	sqlUserByID   = sqlUserSelect + ` WHERE id = ?`
	sqlUserByName = sqlUserSelect + ` WHERE username = ?`
	sqlUserAll    = sqlUserSelect + ` ORDER BY id`
	sqlUserUpdate = `UPDATE users SET username = ?, password_hash = ?, role = ?, token_version = ? WHERE id = ?`
	sqlUserDelete = `DELETE FROM users WHERE id = ?`
	sqlUserAny    = `SELECT EXISTS (SELECT 1 FROM users)`
)

// API-токены: хранится только sha256; last_used_at пишет TouchToken.
const (
	sqlTokenInsert = `INSERT INTO api_tokens (user_id, name, prefix, token_hash, scopes, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`
	sqlTokenSelect = `SELECT id, user_id, name, prefix, token_hash, scopes, created_at, expires_at FROM api_tokens`
	sqlTokenByHash = sqlTokenSelect + ` WHERE token_hash = ?`
	sqlTokenByUser = sqlTokenSelect + ` WHERE user_id = ? ORDER BY id`
	sqlTokenDelete = `DELETE FROM api_tokens WHERE id = ?`
	sqlTokenTouch  = `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`
)

// Личные репозитории и права (чтение публичное — права только на запись).
const (
	sqlRepoInsert = `INSERT INTO repos (name, owner_id, ecosystem, quota_bytes, quota_files, created_at)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
	sqlRepoSelect = `SELECT id, name, owner_id, ecosystem, quota_bytes, quota_files, created_at FROM repos`
	sqlRepoByID   = sqlRepoSelect + ` WHERE id = ?`
	sqlRepoAll    = sqlRepoSelect + ` ORDER BY id`
	sqlRepoUpdate = `UPDATE repos SET name = ?, owner_id = ?, ecosystem = ?, quota_bytes = ?, quota_files = ? WHERE id = ?`
	sqlRepoDelete = `DELETE FROM repos WHERE id = ?`
	sqlPermGrant  = `INSERT INTO repo_perms (repo_id, user_id, perm, created_at) VALUES (?, ?, 'write', ?)`
	sqlPermRevoke = `DELETE FROM repo_perms WHERE repo_id = ? AND user_id = ?`
	sqlPermByRepo = `SELECT repo_id, user_id, created_at FROM repo_perms WHERE repo_id = ? ORDER BY user_id`
)

// Upstream'ы и sync-задачи (resume-курсор — непрозрачная строка).
const (
	sqlRemoteInsert = `INSERT INTO remotes (name, ecosystem, upstream_url, mode, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
	sqlRemoteSelect = `SELECT id, name, ecosystem, upstream_url, mode, enabled, created_at FROM remotes`
	sqlRemoteByID   = sqlRemoteSelect + ` WHERE id = ?`
	sqlRemoteAll    = sqlRemoteSelect + ` ORDER BY id`
	sqlRemoteUpdate = `UPDATE remotes SET name = ?, ecosystem = ?, upstream_url = ?, mode = ?, enabled = ? WHERE id = ?`
	sqlRemoteDelete = `DELETE FROM remotes WHERE id = ?`

	sqlJobInsert = `INSERT INTO sync_jobs (remote_id, state, interval_sec, last_run_at, cursor, updated_at)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
	sqlJobSelect = `SELECT id, remote_id, state, interval_sec, last_run_at, cursor, updated_at FROM sync_jobs`
	sqlJobByID   = sqlJobSelect + ` WHERE id = ?`
	sqlJobAll    = sqlJobSelect + ` ORDER BY id`
	sqlJobUpdate = `UPDATE sync_jobs SET remote_id = ?, state = ?, interval_sec = ?, last_run_at = ?, cursor = ?, updated_at = ? WHERE id = ?`
	sqlJobDelete = `DELETE FROM sync_jobs WHERE id = ?`
)

// Аудит и индекс mutable-объектов.
const (
	sqlAuditInsert = `INSERT INTO audit_log (ts, actor, action, object, result, detail)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
	sqlAuditPage     = `SELECT id, ts, actor, action, object, result, detail FROM audit_log WHERE id > ? ORDER BY id LIMIT ?`
	sqlObjMetaGet    = `SELECT key, etag, size, content_type, last_modified, expires_at FROM object_index WHERE key = ?`
	sqlObjMetaDelete = `DELETE FROM object_index WHERE key = ?`
)

// objectMetaUpsertSQL — upsert object_index через диалект-шим; собирается
// один раз при открытии Store.
func objectMetaUpsertSQL() string {
	return dbtalk.Upsert(dbtalk.SQLite{}, "object_index", "key",
		[]string{"key", "etag", "size", "content_type", "last_modified", "expires_at"})
}

// CreateUser записывает пользователя; ID назначает БД.
func (s *Store) CreateUser(ctx context.Context, u domain.User) (domain.User, error) {
	id, err := call(ctx, s, func() (int64, error) {
		var id int64
		err := s.db.QueryRowContext(ctx, sqlUserInsert,
			u.Username, u.PasswordHash, string(u.Role), u.TokenVersion, dbtalk.Now(u.CreatedAt)).Scan(&id)
		return id, err
	})
	if err != nil {
		return domain.User{}, mapWrite(err, "пользователь", u.Username)
	}
	u.ID = id
	return u, nil
}

// User возвращает пользователя по ID.
func (s *Store) User(ctx context.Context, id int64) (domain.User, error) {
	u, err := call(ctx, s, func() (domain.User, error) {
		return scanUser(s.db.QueryRowContext(ctx, sqlUserByID, id))
	})
	if err != nil {
		return domain.User{}, mapRead(err, "пользователь", strconv.FormatInt(id, 10))
	}
	return u, nil
}

// UserByUsername возвращает пользователя по имени.
func (s *Store) UserByUsername(ctx context.Context, username string) (domain.User, error) {
	u, err := call(ctx, s, func() (domain.User, error) {
		return scanUser(s.db.QueryRowContext(ctx, sqlUserByName, username))
	})
	if err != nil {
		return domain.User{}, mapRead(err, "пользователь", username)
	}
	return u, nil
}

// Users отдаёт всех пользователей по возрастанию ID.
func (s *Store) Users(ctx context.Context) ([]domain.User, error) {
	us, err := call(ctx, s, func() ([]domain.User, error) {
		rows, err := s.db.QueryContext(ctx, sqlUserAll)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.User
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return us, nil
}

// UpdateUser заменяет пользователя целиком.
func (s *Store) UpdateUser(ctx context.Context, u domain.User) error {
	res, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlUserUpdate,
			u.Username, u.PasswordHash, string(u.Role), u.TokenVersion, u.ID)
	})
	if err != nil {
		return mapWrite(err, "пользователь", u.Username)
	}
	return requireAffected(res, "пользователь", u.Username)
}

// DeleteUser удаляет пользователя.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	err := s.exec(ctx, sqlUserDelete, "пользователь", strconv.FormatInt(id, 10), id)
	return err
}

// HasUsers сообщает, есть ли хоть один пользователь.
func (s *Store) HasUsers(ctx context.Context) (bool, error) {
	exists, err := call(ctx, s, func() (bool, error) {
		var exists bool
		err := s.db.QueryRowContext(ctx, sqlUserAny).Scan(&exists)
		return exists, err
	})
	return exists, err
}

// scanUser читает строку users (sql.Row или sql.Rows).
func scanUser(row interface{ Scan(dest ...any) error }) (domain.User, error) {
	var u domain.User
	var role string
	var createdAt int64
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.TokenVersion, &createdAt); err != nil {
		return domain.User{}, err
	}
	u.Role = domain.Role(role)
	u.CreatedAt = time.Unix(createdAt, 0).UTC()
	return u, nil
}

// CreateToken записывает API-токен; ID назначает БД.
func (s *Store) CreateToken(ctx context.Context, t domain.APIToken) (domain.APIToken, error) {
	id, err := call(ctx, s, func() (int64, error) {
		var id int64
		err := s.db.QueryRowContext(ctx, sqlTokenInsert,
			t.UserID, t.Name, t.Prefix, t.SHA256, joinScopes(t.Scopes),
			dbtalk.Now(t.CreatedAt), nullTime(t.ExpiresAt)).Scan(&id)
		return id, err
	})
	if err != nil {
		return domain.APIToken{}, mapWrite(err, "токен", t.Prefix)
	}
	t.ID = id
	return t, nil
}

// TokenBySHA256 ищет токен по хешу (путь авторизации).
func (s *Store) TokenBySHA256(ctx context.Context, sha256 string) (domain.APIToken, error) {
	t, err := call(ctx, s, func() (domain.APIToken, error) {
		return scanToken(s.db.QueryRowContext(ctx, sqlTokenByHash, sha256))
	})
	if err != nil {
		return domain.APIToken{}, mapRead(err, "токен", sha256)
	}
	return t, nil
}

// TokensByUser отдаёт токены пользователя по возрастанию ID.
func (s *Store) TokensByUser(ctx context.Context, userID int64) ([]domain.APIToken, error) {
	ts, err := call(ctx, s, func() ([]domain.APIToken, error) {
		rows, err := s.db.QueryContext(ctx, sqlTokenByUser, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.APIToken
		for rows.Next() {
			t, err := scanToken(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return ts, nil
}

// DeleteToken удаляет токен.
func (s *Store) DeleteToken(ctx context.Context, id int64) error {
	return s.exec(ctx, sqlTokenDelete, "токен", strconv.FormatInt(id, 10), id)
}

// TouchToken фиксирует время последнего использования токена.
func (s *Store) TouchToken(ctx context.Context, id int64, usedAt time.Time) error {
	_, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlTokenTouch, dbtalk.Now(usedAt), id)
	})
	if err != nil {
		return mapWrite(err, "токен", strconv.FormatInt(id, 10))
	}
	return nil
}

// scanToken читает строку api_tokens.
func scanToken(row interface{ Scan(dest ...any) error }) (domain.APIToken, error) {
	var t domain.APIToken
	var scopes string
	var createdAt int64
	var expires sql.NullInt64
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &t.SHA256,
		&scopes, &createdAt, &expires); err != nil {
		return domain.APIToken{}, err
	}
	t.Scopes = splitScopes(scopes)
	t.CreatedAt = time.Unix(createdAt, 0).UTC()
	t.ExpiresAt = timeFromNull(expires)
	return t, nil
}

// CreateRepo записывает личный репозиторий; ID назначает БД.
func (s *Store) CreateRepo(ctx context.Context, r domain.Repo) (domain.Repo, error) {
	id, err := call(ctx, s, func() (int64, error) {
		var id int64
		err := s.db.QueryRowContext(ctx, sqlRepoInsert,
			r.Name, r.OwnerID, r.Ecosystem, r.Quota.MaxBytes, r.Quota.MaxObjects,
			dbtalk.Now(r.CreatedAt)).Scan(&id)
		return id, err
	})
	if err != nil {
		return domain.Repo{}, mapWrite(err, "репозиторий", r.Name)
	}
	r.ID = id
	return r, nil
}

// Repo возвращает репозиторий по ID.
func (s *Store) Repo(ctx context.Context, id int64) (domain.Repo, error) {
	r, err := call(ctx, s, func() (domain.Repo, error) {
		return scanRepo(s.db.QueryRowContext(ctx, sqlRepoByID, id))
	})
	if err != nil {
		return domain.Repo{}, mapRead(err, "репозиторий", strconv.FormatInt(id, 10))
	}
	return r, nil
}

// Repos отдаёт все репозитории по возрастанию ID.
func (s *Store) Repos(ctx context.Context) ([]domain.Repo, error) {
	rs, err := call(ctx, s, func() ([]domain.Repo, error) {
		rows, err := s.db.QueryContext(ctx, sqlRepoAll)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.Repo
		for rows.Next() {
			r, err := scanRepo(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// UpdateRepo заменяет репозиторий целиком.
func (s *Store) UpdateRepo(ctx context.Context, r domain.Repo) error {
	res, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlRepoUpdate,
			r.Name, r.OwnerID, r.Ecosystem, r.Quota.MaxBytes, r.Quota.MaxObjects, r.ID)
	})
	if err != nil {
		return mapWrite(err, "репозиторий", r.Name)
	}
	return requireAffected(res, "репозиторий", r.Name)
}

// DeleteRepo удаляет репозиторий (права каскадом).
func (s *Store) DeleteRepo(ctx context.Context, id int64) error {
	return s.exec(ctx, sqlRepoDelete, "репозиторий", strconv.FormatInt(id, 10), id)
}

// Grant выдаёт право записи в репозиторий.
func (s *Store) Grant(ctx context.Context, p domain.Perm) error {
	_, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlPermGrant, p.RepoID, p.UserID, dbtalk.Now(p.CreatedAt))
	})
	if err != nil {
		return mapWrite(err, "право", strconv.FormatInt(p.RepoID, 10)+":"+strconv.FormatInt(p.UserID, 10))
	}
	return nil
}

// Revoke отбирает право записи.
func (s *Store) Revoke(ctx context.Context, repoID, userID int64) error {
	return s.exec(ctx, sqlPermRevoke, "право",
		strconv.FormatInt(repoID, 10)+":"+strconv.FormatInt(userID, 10), repoID, userID)
}

// Perms отдаёт права репозитория по возрастанию userID.
func (s *Store) Perms(ctx context.Context, repoID int64) ([]domain.Perm, error) {
	ps, err := call(ctx, s, func() ([]domain.Perm, error) {
		rows, err := s.db.QueryContext(ctx, sqlPermByRepo, repoID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.Perm
		for rows.Next() {
			var p domain.Perm
			var createdAt int64
			if err := rows.Scan(&p.RepoID, &p.UserID, &createdAt); err != nil {
				return nil, err
			}
			p.CreatedAt = time.Unix(createdAt, 0).UTC()
			out = append(out, p)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return ps, nil
}

// scanRepo читает строку repos.
func scanRepo(row interface{ Scan(dest ...any) error }) (domain.Repo, error) {
	var r domain.Repo
	var createdAt int64
	if err := row.Scan(&r.ID, &r.Name, &r.OwnerID, &r.Ecosystem,
		&r.Quota.MaxBytes, &r.Quota.MaxObjects, &createdAt); err != nil {
		return domain.Repo{}, err
	}
	r.CreatedAt = time.Unix(createdAt, 0).UTC()
	return r, nil
}

// CreateRemote записывает upstream.
func (s *Store) CreateRemote(ctx context.Context, r domain.Remote) (domain.Remote, error) {
	id, err := call(ctx, s, func() (int64, error) {
		var id int64
		err := s.db.QueryRowContext(ctx, sqlRemoteInsert,
			r.Name, r.Ecosystem, r.BaseURL, string(r.Mode), r.Enabled,
			dbtalk.Now(r.CreatedAt)).Scan(&id)
		return id, err
	})
	if err != nil {
		return domain.Remote{}, mapWrite(err, "remote", r.Name)
	}
	r.ID = id
	return r, nil
}

// Remote возвращает upstream по ID.
func (s *Store) Remote(ctx context.Context, id int64) (domain.Remote, error) {
	r, err := call(ctx, s, func() (domain.Remote, error) {
		return scanRemote(s.db.QueryRowContext(ctx, sqlRemoteByID, id))
	})
	if err != nil {
		return domain.Remote{}, mapRead(err, "remote", strconv.FormatInt(id, 10))
	}
	return r, nil
}

// Remotes отдаёт все upstream'ы по возрастанию ID.
func (s *Store) Remotes(ctx context.Context) ([]domain.Remote, error) {
	rs, err := call(ctx, s, func() ([]domain.Remote, error) {
		rows, err := s.db.QueryContext(ctx, sqlRemoteAll)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.Remote
		for rows.Next() {
			r, err := scanRemote(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// UpdateRemote заменяет upstream целиком.
func (s *Store) UpdateRemote(ctx context.Context, r domain.Remote) error {
	res, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlRemoteUpdate,
			r.Name, r.Ecosystem, r.BaseURL, string(r.Mode), r.Enabled, r.ID)
	})
	if err != nil {
		return mapWrite(err, "remote", r.Name)
	}
	return requireAffected(res, "remote", r.Name)
}

// DeleteRemote удаляет upstream (задачи каскадом).
func (s *Store) DeleteRemote(ctx context.Context, id int64) error {
	return s.exec(ctx, sqlRemoteDelete, "remote", strconv.FormatInt(id, 10), id)
}

// scanRemote читает строку remotes.
func scanRemote(row interface{ Scan(dest ...any) error }) (domain.Remote, error) {
	var r domain.Remote
	var mode string
	var createdAt int64
	if err := row.Scan(&r.ID, &r.Name, &r.Ecosystem, &r.BaseURL, &mode, &r.Enabled, &createdAt); err != nil {
		return domain.Remote{}, err
	}
	r.Mode = domain.RemoteMode(mode)
	r.CreatedAt = time.Unix(createdAt, 0).UTC()
	return r, nil
}

// CreateJob записывает sync-задачу; ID назначает БД.
func (s *Store) CreateJob(ctx context.Context, j domain.SyncJob) (domain.SyncJob, error) {
	id, err := call(ctx, s, func() (int64, error) {
		var id int64
		err := s.db.QueryRowContext(ctx, sqlJobInsert,
			j.RemoteID, string(j.State), int64(j.Interval/time.Second),
			nullTime(j.LastRunAt), j.Cursor, dbtalk.Now(j.UpdatedAt)).Scan(&id)
		return id, err
	})
	if err != nil {
		return domain.SyncJob{}, mapWrite(err, "sync-задача", strconv.FormatInt(j.RemoteID, 10))
	}
	j.ID = id
	return j, nil
}

// Job возвращает задачу по ID.
func (s *Store) Job(ctx context.Context, id int64) (domain.SyncJob, error) {
	j, err := call(ctx, s, func() (domain.SyncJob, error) {
		return scanJob(s.db.QueryRowContext(ctx, sqlJobByID, id))
	})
	if err != nil {
		return domain.SyncJob{}, mapRead(err, "sync-задача", strconv.FormatInt(id, 10))
	}
	return j, nil
}

// Jobs отдаёт все задачи по возрастанию ID.
func (s *Store) Jobs(ctx context.Context) ([]domain.SyncJob, error) {
	js, err := call(ctx, s, func() ([]domain.SyncJob, error) {
		rows, err := s.db.QueryContext(ctx, sqlJobAll)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.SyncJob
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, j)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return js, nil
}

// UpdateJob заменяет задачу целиком (состояние, курсор, метки).
func (s *Store) UpdateJob(ctx context.Context, j domain.SyncJob) error {
	res, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlJobUpdate,
			j.RemoteID, string(j.State), int64(j.Interval/time.Second),
			nullTime(j.LastRunAt), j.Cursor, dbtalk.Now(j.UpdatedAt), j.ID)
	})
	if err != nil {
		return mapWrite(err, "sync-задача", strconv.FormatInt(j.ID, 10))
	}
	return requireAffected(res, "sync-задача", strconv.FormatInt(j.ID, 10))
}

// DeleteJob удаляет задачу.
func (s *Store) DeleteJob(ctx context.Context, id int64) error {
	return s.exec(ctx, sqlJobDelete, "sync-задача", strconv.FormatInt(id, 10), id)
}

// scanJob читает строку sync_jobs.
func scanJob(row interface{ Scan(dest ...any) error }) (domain.SyncJob, error) {
	var j domain.SyncJob
	var state string
	var intervalSec int64
	var lastRun, updatedAt sql.NullInt64
	if err := row.Scan(&j.ID, &j.RemoteID, &state, &intervalSec, &lastRun, &j.Cursor, &updatedAt); err != nil {
		return domain.SyncJob{}, err
	}
	j.State = domain.SyncState(state)
	j.Interval = time.Duration(intervalSec) * time.Second
	j.LastRunAt = timeFromNull(lastRun)
	j.UpdatedAt = time.Unix(updatedAt.Int64, 0).UTC()
	return j, nil
}

// Record пишет запись аудита.
func (s *Store) Record(ctx context.Context, e domain.AuditEntry) error {
	_, err := call(ctx, s, func() (int64, error) {
		var id int64
		err := s.db.QueryRowContext(ctx, sqlAuditInsert,
			dbtalk.Now(e.At), e.Actor, e.Action, e.Object, e.Result, e.Detail).Scan(&id)
		return id, err
	})
	return err
}

// AuditEntries — страница записей с ID строго больше afterID по
// возрастанию ID (keyset-пагинация).
func (s *Store) AuditEntries(ctx context.Context, afterID int64, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 {
		limit = auditDefaultLimit
	}
	es, err := call(ctx, s, func() ([]domain.AuditEntry, error) {
		rows, err := s.db.QueryContext(ctx, sqlAuditPage, afterID, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []domain.AuditEntry
		for rows.Next() {
			var e domain.AuditEntry
			var ts int64
			if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Object, &e.Result, &e.Detail); err != nil {
				return nil, err
			}
			e.At = time.Unix(ts, 0).UTC()
			out = append(out, e)
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return es, nil
}

// ObjectMeta возвращает индексную запись mutable-объекта.
func (s *Store) ObjectMeta(ctx context.Context, key string) (domain.ObjectMeta, error) {
	m, err := call(ctx, s, func() (domain.ObjectMeta, error) {
		return scanObjectMeta(s.db.QueryRowContext(ctx, sqlObjMetaGet, key))
	})
	if err != nil {
		return domain.ObjectMeta{}, mapRead(err, "метаданные объекта", key)
	}
	return m, nil
}

// PutObjectMeta — upsert индексной записи.
func (s *Store) PutObjectMeta(ctx context.Context, m domain.ObjectMeta) error {
	_, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, s.upsertObjectMeta,
			m.Key, m.ETag, m.Size, m.ContentType, nullTime(m.LastModified), nullTime(m.ExpiresAt))
	})
	if err != nil {
		return mapWrite(err, "метаданные объекта", m.Key)
	}
	return nil
}

// DeleteObjectMeta идемпотентно удаляет запись (0 строк — не ошибка).
func (s *Store) DeleteObjectMeta(ctx context.Context, key string) error {
	_, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlObjMetaDelete, key)
	})
	return err
}

// scanObjectMeta читает строку object_index.
func scanObjectMeta(row interface{ Scan(dest ...any) error }) (domain.ObjectMeta, error) {
	var m domain.ObjectMeta
	var lastModified, expires sql.NullInt64
	if err := row.Scan(&m.Key, &m.ETag, &m.Size, &m.ContentType, &lastModified, &expires); err != nil {
		return domain.ObjectMeta{}, err
	}
	m.LastModified = timeFromNull(lastModified)
	m.ExpiresAt = timeFromNull(expires)
	return m, nil
}

// exec — DELETE c требованием затронутой строки: отсутствие сущности —
// NotFound, а не молчаливый успех.
func (s *Store) exec(ctx context.Context, query, what, key string, args ...any) error {
	res, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, query, args...)
	})
	if err != nil {
		return mapWrite(err, what, key)
	}
	return requireAffected(res, what, key)
}

// requireAffected превращает 0 затронутых строк в NotFound.
func requireAffected(res sql.Result, what, key string) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return &domain.NotFoundError{What: what, Key: key}
	}
	return nil
}

// mapRead переводит ошибки чтения: отсутствие строки — NotFound.
func mapRead(err error, what, key string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{What: what, Key: key}
	}
	return err
}

// mapWrite переводит ошибки записи: UNIQUE/PK — «уже существует»,
// FK/прочие ограничения — конфликт с причиной.
func mapWrite(err error, what, key string) error {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return err
	}
	switch serr.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return &domain.ConflictError{What: what, Key: key}
	case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
		return &domain.ConflictError{What: what, Key: key, Reason: "нарушение внешнего ключа"}
	case sqlite3.SQLITE_CONSTRAINT:
		return &domain.ConflictError{What: what, Key: key, Reason: "нарушение ограничения целостности"}
	}
	return err
}

// joinScopes/splitScopes — сериализация scopes: разделитель «,»
// безопасен, внутри scope запятых нет.
func joinScopes(scopes []domain.Scope) string {
	parts := make([]string, len(scopes))
	for i, sc := range scopes {
		parts[i] = string(sc)
	}
	return strings.Join(parts, ",")
}

// splitScopes разбирает колонку scopes обратно в срез.
func splitScopes(joined string) []domain.Scope {
	if joined == "" {
		return nil
	}
	parts := strings.Split(joined, ",")
	scopes := make([]domain.Scope, len(parts))
	for i, p := range parts {
		scopes[i] = domain.Scope(p)
	}
	return scopes
}

// nullTime — аргумент записи опциональной временной колонки: нулевое
// время домена → NULL («никогда»).
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return dbtalk.Now(t)
}

// timeFromNull — обратное преобразование NULL-колонки.
func timeFromNull(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0).UTC()
}
