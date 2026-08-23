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

package mirror

import (
	"context"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

func TestSchedulerStartsRunnersForMirrorRemotes(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	// mirror с интервалом — должен попасть в планировщик
	mirror, _ := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "m", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: time.Hour,
	})
	// proxy — не должен
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "p", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeProxy,
		Enabled: true, SyncInterval: time.Hour,
	})
	// mirror без интервала — не должен
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "mi", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: 0,
	})
	// выключенный mirror — не должен
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "md", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: false, SyncInterval: time.Hour,
	})

	sched := NewScheduler(nil, remotes, testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, time.Minute)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	sched.mu.Lock()
	got := len(sched.runners)
	sched.mu.Unlock()
	if got != 1 {
		t.Fatalf("runners = %d, хочу 1 (только mirror+enabled+interval)", got)
	}
	if _, ok := sched.runners[mirror.ID]; !ok {
		t.Errorf("runner для mirror не запущен")
	}
	// остановим и убедимся, что wg сошёлся
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sched.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestSchedulerNextIntervalWithJitter(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	sched := NewScheduler(nil, remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"),
		clock, 10*time.Minute)
	r := domain.Remote{ID: 1, SyncInterval: time.Hour}
	got := sched.nextInterval(r)
	// база = 1h; jitter = 0..10m; фиксированный rand даёт конкретное
	// число из хвоста UUID. Проверяем диапазон, не конкретное значение.
	if got < time.Hour || got > time.Hour+10*time.Minute {
		t.Errorf("nextInterval = %v, хочу в [1h, 1h10m]", got)
	}
}

func TestSchedulerNextIntervalNoJitter(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	sched := NewScheduler(nil, remotes, testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, 0)
	r := domain.Remote{ID: 1, SyncInterval: time.Hour}
	if got := sched.nextInterval(r); got != time.Hour {
		t.Errorf("nextInterval без джиттера = %v, хочу 1h", got)
	}
}

func TestShouldRun(t *testing.T) {
	cases := []struct {
		name string
		r    domain.Remote
		want bool
	}{
		{"mirror+enabled+interval", domain.Remote{Mode: domain.ModeMirror, Enabled: true, SyncInterval: time.Hour}, true},
		{"proxy", domain.Remote{Mode: domain.ModeProxy, Enabled: true, SyncInterval: time.Hour}, false},
		{"disabled", domain.Remote{Mode: domain.ModeMirror, Enabled: false, SyncInterval: time.Hour}, false},
		{"no interval", domain.Remote{Mode: domain.ModeMirror, Enabled: true, SyncInterval: 0}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldRun(c.r); got != c.want {
				t.Errorf("shouldRun = %v, хочу %v", got, c.want)
			}
		})
	}
}
