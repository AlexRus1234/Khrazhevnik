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

package registry

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/port"
)

// resetForTesting очищает реестр между тестами (глобальное состояние
// — суть compile-time реестра; тесты пакета гоняются последовательно).
func resetForTesting(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storage = map[string]StorageFactory{}
	s.db = map[string]DBFactory{}
	s.ecosystem = map[string]EcosystemFactory{}
	s.repoadapter = map[string]RepoAdapterFactory{}
	s.signer = map[string]SignerFactory{}
	s.narsigner = map[string]NarSignerFactory{}
}

func TestStorageRegisterAndLookup(t *testing.T) {
	resetForTesting(t)
	sentinel := errors.New("boom")
	RegisterStorage("fs", func(config.Storage) (port.Storage, error) { return nil, sentinel })

	fn, err := Storage("fs")
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := fn(config.Storage{}); !errors.Is(cerr, sentinel) {
		t.Errorf("фабрика вернула %v, хочу sentinel", cerr)
	}
}

func TestLookupUnknownListsAvailable(t *testing.T) {
	resetForTesting(t)
	RegisterStorage("fs", func(config.Storage) (port.Storage, error) { return nil, nil })
	RegisterDB("sqlite", func(config.Database) (CatalogSet, error) { return CatalogSet{}, nil })

	if _, err := Storage("s3"); err == nil || !strings.Contains(err.Error(), "доступны: fs") {
		t.Errorf("lookup неизвестного хранилища: %v", err)
	}
	if _, err := DB("postgres"); err == nil ||
		!strings.Contains(err.Error(), `драйвер БД "postgres"`) ||
		!strings.Contains(err.Error(), "доступны: sqlite") {
		t.Errorf("lookup неизвестной БД: %v", err)
	}
	if _, err := Ecosystem("apt"); err == nil || !strings.Contains(err.Error(), "модули не слинкованы") {
		t.Errorf("lookup в пустой карте экосистем: %v", err)
	}
}

func TestEcosystemsListing(t *testing.T) {
	resetForTesting(t)
	eco := func(config.Ecosystem, EcosystemDeps) (port.Ecosystem, error) { return nil, nil }
	RegisterEcosystem("rpm-md", eco)
	RegisterEcosystem("apt", eco)
	RegisterEcosystem("pacman", eco)

	got := Ecosystems()
	want := []string{"apt", "pacman", "rpm-md"}
	if len(got) != len(want) {
		t.Fatalf("Ecosystems() = %v, хочу %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ecosystems() = %v, хочу %v", got, want)
		}
	}
}

func TestEmpty(t *testing.T) {
	resetForTesting(t)
	if !Empty() {
		t.Fatal("пустой реестр не распознан")
	}
	RegisterEcosystem("apt", func(config.Ecosystem, EcosystemDeps) (port.Ecosystem, error) { return nil, nil })
	if Empty() {
		t.Fatal("реестр с экосистемой считается пустым")
	}
}

func TestNarSignerRegisterAndLookup(t *testing.T) {
	resetForTesting(t)
	sentinel := errors.New("narboom")
	RegisterNarSigner("ed25519", func(config.Signing) (port.NarSigner, error) { return nil, sentinel })

	fn, err := NarSigner("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := fn(config.Signing{}); !errors.Is(cerr, sentinel) {
		t.Errorf("фабрика вернула %v, хочу sentinel", cerr)
	}
	if _, err := NarSigner("unknown"); err == nil || !strings.Contains(err.Error(), "доступны: ed25519") {
		t.Errorf("lookup неизвестного nar-подписчика: %v", err)
	}
}

func TestRegisterDuplicatesPanic(t *testing.T) {
	resetForTesting(t)
	storage := func(config.Storage) (port.Storage, error) { return nil, nil }
	db := func(config.Database) (CatalogSet, error) { return CatalogSet{}, nil }
	eco := func(config.Ecosystem, EcosystemDeps) (port.Ecosystem, error) { return nil, nil }
	nar := func(config.Signing) (port.NarSigner, error) { return nil, nil }

	cases := []struct {
		name string
		reg  func()
	}{
		{"storage", func() { RegisterStorage("dup", storage) }},
		{"db", func() { RegisterDB("dup", db) }},
		{"ecosystem", func() { RegisterEcosystem("dup", eco) }},
		{"nar", func() { RegisterNarSigner("dup", nar) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.reg() // первая регистрация
			defer func() {
				if recover() == nil {
					t.Error("ожидался panic на повторной регистрации")
				}
			}()
			c.reg() // вторая — программистская ошибка
		})
	}
}

func TestRegisterInvalidPanics(t *testing.T) {
	resetForTesting(t)
	cases := []struct {
		name string
		reg  func()
	}{
		{"пустое имя", func() { RegisterStorage("", func(config.Storage) (port.Storage, error) { return nil, nil }) }},
		{"nil-фабрика", func() { RegisterStorage("x", nil) }},
		{"nil БД", func() { RegisterDB("x", nil) }},
		{"nil экосистема", func() { RegisterEcosystem("x", nil) }},
		{"nil nar", func() { RegisterNarSigner("x", nil) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("ожидался panic на некорректной регистрации")
				}
			}()
			c.reg()
		})
	}
}

func TestConcurrentRegisterAndLookup(t *testing.T) {
	resetForTesting(t)
	storage := func(config.Storage) (port.Storage, error) { return nil, nil }
	db := func(config.Database) (CatalogSet, error) { return CatalogSet{}, nil }

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			RegisterStorage("fs"+strconv.Itoa(i), storage)
		}()
		go func() {
			defer wg.Done()
			RegisterDB("db"+strconv.Itoa(i), db)
		}()
		go func() {
			defer wg.Done() // конкурентные lookup'ы без регистраций
			_, _ = Storage("fs0")
			_, _ = DB("db0")
			_, _ = Ecosystem("apt")
			_ = Ecosystems()
			_ = Empty()
		}()
	}
	wg.Wait()

	if got := len(Ecosystems()); got != 0 {
		t.Errorf("экосистем зарегистрировано %d, хочу 0", got)
	}
}
