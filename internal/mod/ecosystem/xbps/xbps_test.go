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

package xbps

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/testutil"
)

func newTestAdapter(t *testing.T) *Adapter {
	t.Helper()
	a, err := New(testutil.NewFakeRemoteStore(), testutil.NewManualClock(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNewValidatesDeps(t *testing.T) {
	if _, err := New(nil, testutil.NewManualClock(time.Now())); err == nil {
		t.Error("New(nil, clock) должен ошибаться")
	}
	if _, err := New(testutil.NewFakeRemoteStore(), nil); err == nil {
		t.Error("New(remotes, nil) должен ошибаться")
	}
}

func TestName(t *testing.T) {
	if got := newTestAdapter(t).Name(); got != "xbps" {
		t.Errorf("Name() = %q, хочу xbps", got)
	}
}

func TestURLPrefix(t *testing.T) {
	if got := newTestAdapter(t).URLPrefix(); got != "xbps" {
		t.Errorf("URLPrefix() = %q, хочу xbps", got)
	}
}

// TestRegistration — пакет зарегистрировался в compile-time реестре
// через init() (blank-import в wire.go добавит его в сборку бинаря).
func TestRegistration(t *testing.T) {
	if !slices.Contains(registry.Ecosystems(), Name) {
		t.Errorf("registry.Ecosystems() = %v, хочу среди них %q", registry.Ecosystems(), Name)
	}
}

type classifyCase struct {
	path string
	kind domain.Kind
	ttl  time.Duration
}

func TestClassifyTable(t *testing.T) {
	a := newTestAdapter(t)
	cases := []classifyCase{
		// Mutable{TTL 5m}: индекс <arch>-repodata — плоский файл в корне.
		{"x86_64-repodata", domain.KindMutable, mutableIndexTTL},
		{"aarch64-repodata", domain.KindMutable, mutableIndexTTL},
		// Immutable: реальные имена пакетов Void (регистрочувствительны).
		{"Mustache-4.1_1.x86_64.xbps", domain.KindImmutable, 0},
		{"libstdc++-13.2.0_1.x86_64.xbps", domain.KindImmutable, 0},
		{"xbps-0.60.7_1.x86_64.xbps.sig2", domain.KindImmutable, 0},
		{"xbps-0.60.7_1.x86_64.xbps.sig", domain.KindImmutable, 0},
		// repodata во вложенном каталоге не матчится правилом корня.
		{"nested/x86_64-repodata", domain.KindMutable, mutableUnknownTTL},
		// Unknown → conservative Mutable{TTL 1m}.
		{"some/random/path.dat", domain.KindMutable, mutableUnknownTTL},
	}
	for _, tc := range cases {
		got, err := a.Classify(tc.path)
		if err != nil {
			t.Errorf("Classify(%q) err = %v", tc.path, err)
			continue
		}
		if got.Kind != tc.kind {
			t.Errorf("Classify(%q).Kind = %q, хочу %q", tc.path, got.Kind, tc.kind)
		}
		if tc.kind == domain.KindMutable && got.TTL != tc.ttl {
			t.Errorf("Classify(%q).TTL = %v, хочу %v", tc.path, got.TTL, tc.ttl)
		}
	}
}

func TestClassifyEmptyPath(t *testing.T) {
	a := newTestAdapter(t)
	_, err := a.Classify("")
	var ve *domain.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Classify(\"\") = %v, хочу *ValidationError", err)
	}
}

func TestClassifyRulesCovered(t *testing.T) {
	a := newTestAdapter(t)
	covered := make(map[string]bool, len(a.rules))
	for _, r := range a.rules {
		covered[r.name] = false
	}
	for _, tc := range []string{
		"Mustache-4.1_1.x86_64.xbps",
		"x86_64-repodata",
		"xbps-0.60.7_1.x86_64.xbps.sig2",
		"xbps-0.60.7_1.x86_64.xbps.sig",
	} {
		for _, r := range a.rules {
			if r.re.MatchString(tc) {
				covered[r.name] = true
			}
		}
	}
	for name, ok := range covered {
		if !ok {
			t.Errorf("правило %q не покрыто ни одним тест-кейсом", name)
		}
	}
}

// fakeRemotes — RemoteStore с предзаполненными remotes для Resolve.
type fakeRemotes struct{ rs []domain.Remote }

func (f fakeRemotes) CreateRemote(context.Context, domain.Remote) (domain.Remote, error) {
	return domain.Remote{}, nil
}
func (f fakeRemotes) Remote(context.Context, int64) (domain.Remote, error) {
	return domain.Remote{}, nil
}
func (f fakeRemotes) Remotes(context.Context) ([]domain.Remote, error)  { return f.rs, nil }
func (f fakeRemotes) UpdateRemote(context.Context, domain.Remote) error { return nil }
func (f fakeRemotes) DeleteRemote(context.Context, int64) error         { return nil }

func newResolveAdapter(t *testing.T, rs ...domain.Remote) *Adapter {
	t.Helper()
	a, err := New(fakeRemotes{rs: rs}, testutil.NewManualClock(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestResolveKnownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 9, Name: "void", Ecosystem: "xbps",
		BaseURL: "https://repo-default.voidlinux.org/current", Enabled: true,
	})
	target, ok := a.Resolve("/xbps/void/Mustache-4.1_1.x86_64.xbps")
	if !ok {
		t.Fatal("Resolve существующего remote = false")
	}
	wantURL := "https://repo-default.voidlinux.org/current/Mustache-4.1_1.x86_64.xbps"
	if target.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, хочу %q", target.UpstreamURL, wantURL)
	}
	if target.UpstreamPath != "/Mustache-4.1_1.x86_64.xbps" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/xbps/9/Mustache-4.1_1.x86_64.xbps" {
		t.Errorf("StorageKey = %q, хочу регистр «Mustache» сохранённым", target.StorageKey)
	}
}

func TestResolveUnknownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "void", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/xbps/fedoris/x86_64-repodata"); ok {
		t.Error("Resolve неизвестного remote должен дать false")
	}
}

func TestResolveDisabledRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "void", BaseURL: "https://x", Enabled: false})
	if _, ok := a.Resolve("/xbps/void/x86_64-repodata"); ok {
		t.Error("Resolve выключенного remote должен дать false")
	}
}

func TestResolveWrongEcosystemPrefix(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "void", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apk/void/x86_64-repodata",
		"/rpm/void/x86_64-repodata",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) с чужим префиксом должен дать false", path)
		}
	}
}

func TestResolveTraversalRemoteName(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "void", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/xbps/../etc/passwd",
		"/xbps/./etc/passwd",
		"/xbps//etc/passwd",
		"/xbps//",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) должен отвергнуть traversal, но дал ok", path)
		}
	}
}
