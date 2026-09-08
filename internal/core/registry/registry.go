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
	"fmt"
	"slices"
	"strings"
	"sync"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/port"
)

// CatalogSet — полный набор catalog-store'ов, который обязан отдать
// драйвер БД: один адаптер реализует все интерфейсы порта каталога,
// потребители (engine) берут из набора нужные срезы.
type CatalogSet struct {
	Users    port.UserStore
	Tokens   port.TokenStore
	Repos    port.RepoStore
	Remotes  port.RemoteStore
	Jobs     port.JobStore
	Audit    port.AuditLog
	ObjIndex port.ObjectIndex
	// Stats — снапшот per-eco счётчиков статистики кеша (сессия 95):
	// переживает рестарт процесса.
	Stats port.StatsStore
	// Revocations — персистентный отзыв JWT-сессий (сессия 25):
	// logout переживает рестарт процесса.
	Revocations port.SessionRevocationStore
}

// Фабрики модулей: вызываются в cmd/khrazhevnik/wire.go с секцией
// конфигурации соответствующего драйвера.

// StorageFactory создаёт хранилище объектов (mod/storage/*).
type StorageFactory = func(cfg config.Storage) (port.Storage, error)

// DBFactory открывает каталог БД и возвращает набор store'ов
// (mod/db/*).
type DBFactory = func(cfg config.Database) (CatalogSet, error)

// EcosystemDeps — зависимости адаптера экосистемы из каталога и
// инфраструктуры: то, что нужно для разрешения remotes по пути и
// инвалидации кеша remotes по TTL. Зависимости, появляющиеся с
// новыми движками (sync-воркеры зеркал — сессия 11), дописываются
// сюда; порции остаются опционально-нулевыми, если экосистема их
// не использует (проверка — в фабрике).
type EcosystemDeps struct {
	Remotes port.RemoteStore
	Clock   port.Clock
}

// EcosystemFactory создаёт адаптер экосистемы (mod/ecosystem/*).
// cfg — секция [ecosystem.<имя>] (пока только Enabled); deps —
// срезы каталога и инфраструктуры, нужные адаптеру для работы.
type EcosystemFactory = func(cfg config.Ecosystem, deps EcosystemDeps) (port.Ecosystem, error)

// RepoAdapterFactory создаёт адаптер личного репозитория (mod/
// ecosystem/* — gen.go). Без конфига: экосистемы personal-repo
// переиспользуют то же имя, что и в ecosystem; генератор индексов
// не зависит от remotes/clock (читает из Storage напрямую).
type RepoAdapterFactory = func() (port.RepoAdapter, error)

// SignerFactory создаёт подписчик метаданных личных репозиториев
// (mod/sign/openpgp — сессия 15). cfg — секция [signing]: keys_dir +
// опциональная passphrase; clock — источник времени для меток подписей
// (packet.Config.Now; сессия 24 — правило «время только через
// port.Clock»). Единственный продакшен-подписчик v1 —
// openpgp (ed25519 для nix — сессия 16, живёт вне port.Signer). nil
// от фабрики или отсутствие регистрации — publish работает без
// подписи (apt с trusted=yes; /key.asc отдаёт 404 через
// wildcard-раздачу репо — ключа нет).
type SignerFactory = func(cfg config.Signing, clock port.Clock) (port.Signer, error)

// NarSignerFactory создаёт nix narinfo-подписчик (mod/sign/ed25519 —
// сессия 16, живёт вне port.Signer: своя, более простая модель подписи
// «name:signature»). cfg — секция [signing]: keys_dir (ключ
// ed25519 персистится рядом с openpgp, отдельным файлом). nil от фабрики
// или отсутствие регистрации — nix narinfo не переподписывается.
type NarSignerFactory = func(cfg config.Signing) (port.NarSigner, error)

// state — закрытое глобальное состояние реестра. Единственное
// разрешённое package-level состояние вне cmd: compile-time реестр
// (init()-регистрация из mod/*) без него не собрать — см. AGENTS.md.
type state struct {
	mu          sync.RWMutex
	storage     map[string]StorageFactory
	db          map[string]DBFactory
	ecosystem   map[string]EcosystemFactory
	repoadapter map[string]RepoAdapterFactory
	signer      map[string]SignerFactory
	narsigner   map[string]NarSignerFactory
}

var s = &state{
	storage:     map[string]StorageFactory{},
	db:          map[string]DBFactory{},
	ecosystem:   map[string]EcosystemFactory{},
	repoadapter: map[string]RepoAdapterFactory{},
	signer:      map[string]SignerFactory{},
	narsigner:   map[string]NarSignerFactory{},
}

// RegisterStorage регистрирует фабрику хранилища. Вызывается из
// init() модулей; пустое имя, nil-фабрика или повторная регистрация
// — panic на инициализации (ошибка программиста, а не рантайма).
func RegisterStorage(name string, factory StorageFactory) {
	if factory == nil {
		panic("registry: регистрация хранилища с nil-фабрикой: " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registerLocked("хранилище", name, s.storage, factory)
}

// RegisterDB регистрирует фабрику каталога БД.
func RegisterDB(name string, factory DBFactory) {
	if factory == nil {
		panic("registry: регистрация БД с nil-фабрикой: " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registerLocked("БД", name, s.db, factory)
}

// RegisterEcosystem регистрирует фабрику адаптера экосистемы.
func RegisterEcosystem(name string, factory EcosystemFactory) {
	if factory == nil {
		panic("registry: регистрация экосистемы с nil-фабрикой: " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registerLocked("экосистема", name, s.ecosystem, factory)
}

// RegisterRepoAdapter регистрирует фабрику адаптера личного репо
// (mod/ecosystem/*/gen.go). Имя совпадает с именем экосистемы.
func RegisterRepoAdapter(name string, factory RepoAdapterFactory) {
	if factory == nil {
		panic("registry: регистрация repo-адаптера с nil-фабрикой: " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registerLocked("repo-адаптер", name, s.repoadapter, factory)
}

// RegisterSigner регистрирует фабрику подписчика метаданных
// (mod/sign/openpgp). Единственная регистрация v1 — «openpgp».
func RegisterSigner(name string, factory SignerFactory) {
	if factory == nil {
		panic("registry: регистрация подписчика с nil-фабрикой: " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registerLocked("подписчик", name, s.signer, factory)
}

// RegisterNarSigner регистрирует фабрику nix narinfo-подписчика
// (mod/sign/ed25519 — сессия 16). Регистрация v1 — «ed25519».
func RegisterNarSigner(name string, factory NarSignerFactory) {
	if factory == nil {
		panic("registry: регистрация nar-подписчика с nil-фабрикой: " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registerLocked("nar-подписчик", name, s.narsigner, factory)
}

// registerLocked — общее ядро регистрации; mu уже захвачена.
func registerLocked[T any](kind, name string, m map[string]T, fn T) {
	if name == "" {
		panic("registry: регистрация " + kind + " с пустым именем")
	}
	if _, dup := m[name]; dup {
		panic(fmt.Sprintf("registry: повторная регистрация %s %q", kind, name))
	}
	m[name] = fn
}

// Storage возвращает фабрику хранилища по имени; неизвестное имя —
// ошибка с перечнем доступных драйверов.
func Storage(name string) (StorageFactory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fn, ok := s.storage[name]; ok {
		return fn, nil
	}
	return nil, unknownDriver("хранилище", name, sortedNames(s.storage))
}

// DB возвращает фабрику каталога по имени драйвера.
func DB(name string) (DBFactory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fn, ok := s.db[name]; ok {
		return fn, nil
	}
	return nil, unknownDriver("БД", name, sortedNames(s.db))
}

// Ecosystem возвращает фабрику адаптера экосистемы по имени.
func Ecosystem(name string) (EcosystemFactory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fn, ok := s.ecosystem[name]; ok {
		return fn, nil
	}
	return nil, unknownDriver("экосистема", name, sortedNames(s.ecosystem))
}

// RepoAdapter возвращает фабрику адаптера личного репо по имени
// экосистемы. nil-фабрика на старте — publish-движок работает без
// генератора (upload разрешён, reindex падает с UnsupportedError).
func RepoAdapter(name string) (RepoAdapterFactory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fn, ok := s.repoadapter[name]; ok {
		return fn, nil
	}
	return nil, unknownDriver("repo-адаптер", name, sortedNames(s.repoadapter))
}

// Signer возвращает фабрику подписчика по имени. Отсутствие
// регистрации — не ошибка старта: publish работает без подписи
// (вызывающий логирует и оставляет nil-Signer).
func Signer(name string) (SignerFactory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fn, ok := s.signer[name]; ok {
		return fn, nil
	}
	return nil, unknownDriver("подписчик", name, sortedNames(s.signer))
}

// NarSigner возвращает фабрику nix narinfo-подписчика по имени.
// Отсутствие регистрации — не ошибка старта: nix narinfo не
// переподписывается (вызывающий логирует и оставляет nil).
func NarSigner(name string) (NarSignerFactory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fn, ok := s.narsigner[name]; ok {
		return fn, nil
	}
	return nil, unknownDriver("nar-подписчик", name, sortedNames(s.narsigner))
}

// Ecosystems — отсортированные имена зарегистрированных экосистем
// (для сборки адаптеров в wire и логов старта).
func Ecosystems() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedNames(s.ecosystem)
}

// Empty сообщает, что не слинкован ни один модуль: сборка без
// blank-import'ов. main в этом случае стартует в деградированном
// режиме (только /healthz) с громкой ошибкой в логе.
func Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.storage) == 0 && len(s.db) == 0 && len(s.ecosystem) == 0 && len(s.repoadapter) == 0 && len(s.signer) == 0 && len(s.narsigner) == 0
}

// unknownDriver — дружелюбная ошибка lookup'а.
func unknownDriver(kind, name string, available []string) error {
	if len(available) == 0 {
		return fmt.Errorf("реестр: неизвестный драйвер %s %q: модули не слинкованы (сборка без blank-import'ов)", kind, name)
	}
	return fmt.Errorf("реестр: неизвестный драйвер %s %q (доступны: %s)", kind, name, strings.Join(available, ", "))
}

// sortedNames — имена фабрик по алфавиту (стабильные сообщения).
func sortedNames[T any](m map[string]T) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
