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

// Реализация port.StatsStore — снапшот per-eco счётчиков статистики
// кеша (cache_stats). Запросы — копия sqlite-адаптера с нумерованными
// плейсхолдерами $n. Флаш/загрузка снапшота — сессия 96.

package postgres

import (
	"context"
	"database/sql"
	"time"

	"khrazhevnik/internal/core/dbtalk"
	"khrazhevnik/internal/core/domain"
)

// Счётчики статистики кеша (cache_stats).
const (
	sqlStatsSelect = `SELECT ecosystem, hits, misses, stale_served, negative_hits, upstream_errors, bytes_from_upstream, bytes_to_clients, packages, updated_at FROM cache_stats`
	sqlStatsAll    = sqlStatsSelect + ` ORDER BY ecosystem`
	sqlStatsDelete = `DELETE FROM cache_stats`
)

// statsUpsertSQL — upsert cache_stats через диалект-шим; собирается
// один раз при открытии Store (прецедент upsertObjectMeta).
func statsUpsertSQL() string {
	return dbtalk.Upsert(dbtalk.Postgres{}, "cache_stats", "ecosystem",
		[]string{"ecosystem", "hits", "misses", "stale_served", "negative_hits",
			"upstream_errors", "bytes_from_upstream", "bytes_to_clients", "packages", "updated_at"})
}

// SaveStatsSnapshot перезаписывает строки снапшота upsert'ом одной
// транзакцией: читатель в другом соединении видит либо старый снапшот
// целиком, либо новый — не смесь по-строчно.
func (s *Store) SaveStatsSnapshot(ctx context.Context, rows []domain.CacheStatsRow) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := call(ctx, s, func() (sql.Result, error) {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }() // после Commit — no-op
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, s.upsertStatsSnapshot,
				r.Ecosystem, r.Hits, r.Misses, r.StaleServed, r.NegativeHits,
				r.UpstreamErrors, r.BytesFromUpstream, r.BytesToClients,
				r.Packages, dbtalk.Now(r.UpdatedAt)); err != nil {
				return nil, err
			}
		}
		return nil, tx.Commit()
	})
	if err != nil {
		return mapWrite(err, "статистика", "cache_stats")
	}
	return nil
}

// StatsSnapshot возвращает снапшот целиком, по экосистемам по алфавиту.
func (s *Store) StatsSnapshot(ctx context.Context) ([]domain.CacheStatsRow, error) {
	rows, err := call(ctx, s, func() ([]domain.CacheStatsRow, error) {
		rs, err := s.db.QueryContext(ctx, sqlStatsAll)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rs.Close() }()
		out := make([]domain.CacheStatsRow, 0, 8)
		for rs.Next() {
			r, err := scanStatsRow(rs)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rs.Err()
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// ResetStats очищает снапшот (сброс статистики админом).
func (s *Store) ResetStats(ctx context.Context) error {
	_, err := call(ctx, s, func() (sql.Result, error) {
		return s.db.ExecContext(ctx, sqlStatsDelete)
	})
	if err != nil {
		return mapWrite(err, "статистика", "cache_stats")
	}
	return nil
}

// scanStatsRow читает строку cache_stats.
func scanStatsRow(row interface{ Scan(dest ...any) error }) (domain.CacheStatsRow, error) {
	var r domain.CacheStatsRow
	var updated int64
	if err := row.Scan(&r.Ecosystem, &r.Hits, &r.Misses, &r.StaleServed, &r.NegativeHits,
		&r.UpstreamErrors, &r.BytesFromUpstream, &r.BytesToClients,
		&r.Packages, &updated); err != nil {
		return domain.CacheStatsRow{}, err
	}
	r.UpdatedAt = time.Unix(updated, 0).UTC()
	return r, nil
}
