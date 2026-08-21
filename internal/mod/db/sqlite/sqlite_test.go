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
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// busyFixture — два независимых пула на одном файле с busy_timeout=0
// (shared-cache не подходит: modernc там ждёт unlock_notify вместо
// мгновенного SQLITE_BUSY): db1 держит write-транзакцию, запись через
// db2 сразу отбивается SQLITE_BUSY.
type busyFixture struct {
	db1, db2 *sql.DB
}

func newBusyFixture(t *testing.T) *busyFixture {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "busy.db") + "?_busy_timeout=0"
	db1, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	// db1 обязан держать транзакцию на одном соединении
	db1.SetMaxOpenConns(1)
	db2.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db1.Close(); _ = db2.Close() })

	if _, err := db1.Exec(`CREATE TABLE probe (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db1.Exec(`BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	if _, err := db1.Exec(`INSERT INTO probe (x) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	return &busyFixture{db1: db1, db2: db2}
}

// lockedWrite — запись через db2: BUSY/LOCKED, пока db1 держит транзакцию.
func (f *busyFixture) lockedWrite() error {
	_, err := f.db2.Exec(`INSERT INTO probe (x) VALUES (2)`)
	return err
}

// release отпускает транзакцию db1.
func (f *busyFixture) release() error {
	_, err := f.db1.Exec(`ROLLBACK`)
	return err
}

func TestIsBusyDetectsRealLock(t *testing.T) {
	f := newBusyFixture(t)
	err := f.lockedWrite()
	if err == nil {
		t.Fatal("запись под чужой write-транзакцию не отклонена")
	}
	if !isBusy(err) {
		t.Fatalf("isBusy(%v) = false", err)
	}
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		t.Fatalf("ошибка не *sqlite.Error: %T", err)
	}
	if err := f.release(); err != nil {
		t.Fatal(err)
	}

	// негатив: нарушение ограничения — не busy
	if _, err := f.db2.Exec(`CREATE TABLE uniq (v TEXT UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db2.Exec(`INSERT INTO uniq (v) VALUES ('a')`); err != nil {
		t.Fatal(err)
	}
	_, dupErr := f.db2.Exec(`INSERT INTO uniq (v) VALUES ('a')`)
	if dupErr == nil || isBusy(dupErr) {
		t.Fatalf("UNIQUE-конфликт попал в isBusy: %v", dupErr)
	}
	if isBusy(nil) || isBusy(sql.ErrNoRows) {
		t.Fatal("isBusy матчит посторонние ошибки")
	}
}
func TestCallRetriesUntilUnlock(t *testing.T) {
	f := newBusyFixture(t)
	st := &Store{sleep: func(time.Duration) {}}

	var slept []time.Duration
	var once sync.Once
	st.sleep = func(d time.Duration) {
		slept = append(slept, d)
		once.Do(func() {
			if err := f.release(); err != nil {
				t.Errorf("release: %v", err)
			}
		})
	}

	_, err := call(context.Background(), st, func() (int64, error) {
		if e := f.lockedWrite(); e != nil {
			return 0, e
		}
		return 1, nil
	})
	if err != nil {
		t.Fatalf("call после разблокировки: %v", err)
	}
	if len(slept) < 1 {
		t.Fatal("retry не сработал ни разу")
	}
	if slept[0] != 50*time.Millisecond {
		t.Fatalf("первая пауза = %v, хочу 50мс", slept[0])
	}
}

func TestCallExhaustsRetries(t *testing.T) {
	f := newBusyFixture(t)
	defer func() { _ = f.release() }()

	var slept []time.Duration
	attempts := 0
	st := &Store{sleep: func(d time.Duration) { slept = append(slept, d) }}

	_, err := call(context.Background(), st, func() (int64, error) {
		attempts++
		return 0, f.lockedWrite()
	})
	if err == nil {
		t.Fatal("исчерпание попыток не вернуло ошибку")
	}
	if !isBusy(err) {
		t.Fatalf("последняя ошибка не busy: %v", err)
	}
	if attempts != 1+busyRetries {
		t.Fatalf("попыток %d, хочу %d", attempts, 1+busyRetries)
	}
	want := []time.Duration{50 * time.Millisecond, 200 * time.Millisecond}
	if len(slept) != len(want) || slept[0] != want[0] || slept[1] != want[1] {
		t.Fatalf("паузы %v, хочу %v", slept, want)
	}
}

func TestCallDoesNotRetryOtherErrors(t *testing.T) {
	slept := false
	st := &Store{sleep: func(time.Duration) { slept = true }}
	calls := 0
	_, err := call(context.Background(), st, func() (int64, error) {
		calls++
		return 0, sql.ErrNoRows
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ошибка изменилась: %v", err)
	}
	if calls != 1 || slept {
		t.Fatalf("не-busy ошибка: попыток %d, sleep=%v", calls, slept)
	}
}
