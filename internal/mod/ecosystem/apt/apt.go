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

// Package apt — адаптер экосистемы Debian/Ubuntu (apt): маппинг путей
// публичного порта /apt/<remote>/<остальной-путь> на upstream и
// классификация объектов по изменчивости. Кеш RemoteStore с
// инвалидацией по TTL (30с) — KISS: новая конфигурация remotes
// подхватывается без перезапуска. Парсер Packages/Release живёт в
// parse.go (переиспользуется зеркалом, сессия 11).
package apt

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// Name — каноническое имя экосистемы и префикс публичных путей.
const Name = "apt"

// Периоды кеширования/ревалидации. remoteCacheTTL — TTL кеша RemoteStore
// (новые/изменённые remotes подхватываются без рестарта); TTL индексов
// mutable объектов задаётся здесь, а не в конфиге — это инвариант
// экосистемы (apt-индексы меняются редко, но подписи обязаны
// ревалидироваться).
const (
	remoteCacheTTL    = 30 * time.Second
	mutableIndexTTL   = 5 * time.Minute
	mutableUnknownTTL = 1 * time.Minute
)

func init() {
	registry.RegisterEcosystem(Name, func(_ config.Ecosystem, deps registry.EcosystemDeps) (port.Ecosystem, error) {
		return New(deps.Remotes, deps.Clock)
	})
}

// Adapter реализует port.Ecosystem для apt.
type Adapter struct {
	remotes port.RemoteStore
	clock   port.Clock
	rules   []compiledRule

	mu          sync.RWMutex
	remoteCache map[string]remoteEntry
	cacheLoaded time.Time
}

// remoteEntry — кеш одной записи RemoteStore по имени: remote и
// момент обновления. err кешируется тоже (БД легла — не долбим её
// каждым запросом, пока TTL не вышел).
type remoteEntry struct {
	remote domain.Remote
	err    error
}

// New создаёт адаптер: remotes — источник upstream-конфигураций,
// clock — время для инвалидации кеша remotes. Правила классификации
// компилируются один раз (регексов ~20 — пренебрежимо).
func New(remotes port.RemoteStore, clock port.Clock) (*Adapter, error) {
	if remotes == nil {
		return nil, fmt.Errorf("apt: RemoteStore обязателен")
	}
	if clock == nil {
		return nil, fmt.Errorf("apt: Clock обязателен")
	}
	return &Adapter{
		remotes:     remotes,
		clock:       clock,
		rules:       compileRules(),
		remoteCache: map[string]remoteEntry{},
	}, nil
}

// Name возвращает имя экосистемы.
func (a *Adapter) Name() string { return Name }

// URLPrefix возвращает префикс путей публичного порта. У apt префикс
// совпадает с именем.
func (a *Adapter) URLPrefix() string { return Name }

// Resolve переводит /apt/<remote-name>/<остальной-путь> в Target.
// false — путь не принадлежит apt или remote неизвестен/выключен.
// Кеш remotes обновляется по TTL 30с: перезапуск не нужен для вновь
// добавленных upstream'ов. UpstreamURL/UpstreamPath сохраняют оригинальный
// регистр (byte-exact к upstream); StorageKey лоуэркейсит путь —
// доменный ключ допускает только [a-z0-9/._-].
func (a *Adapter) Resolve(ecosystemPath string) (port.Target, bool) {
	prefix := "/" + Name + "/"
	if !strings.HasPrefix(ecosystemPath, prefix) {
		return port.Target{}, false
	}
	name, upstreamPath, ok := splitRemotePath(strings.TrimPrefix(ecosystemPath, prefix))
	if !ok {
		return port.Target{}, false
	}
	remote, err := a.lookupRemote(name)
	if err != nil {
		return port.Target{}, false
	}
	if !remote.Enabled {
		return port.Target{}, false
	}
	base := strings.TrimRight(remote.BaseURL, "/")
	return port.Target{
		UpstreamURL:  base + upstreamPath,
		UpstreamPath: upstreamPath,
		StorageKey:   "cache/" + Name + "/" + strconv.FormatInt(remote.ID, 10) + strings.ToLower(upstreamPath),
	}, true
}

// Classify делит объекты apt по изменчивости. Пакеты (pool/) и
// by-hash — immutable; индексы dists/ — mutable{TTL 5m}; всё прочее —
// conservative mutable{TTL 1m} (безопасный дефолт: короткий TTL
// ограничивает отдачу протухших данных). Пустой путь — ошибка
// валидации (не передаётся в движок).
func (a *Adapter) Classify(upstreamPath string) (domain.Class, error) {
	if upstreamPath == "" {
		return domain.Class{}, &domain.ValidationError{What: "путь upstream", Value: upstreamPath, Reason: "пустой"}
	}
	path := strings.TrimPrefix(upstreamPath, "/")
	for _, r := range a.rules {
		if r.re.MatchString(path) {
			return r.class, nil
		}
	}
	return domain.Mutable(mutableUnknownTTL), nil
}

// lookupRemote возвращает Remote по имени из кеша; при истечении TTL
// перечитывает весь список remotes (KISS: remotes обычно единицы).
func (a *Adapter) lookupRemote(name string) (domain.Remote, error) {
	now := a.clock.Now()
	a.mu.RLock()
	if now.Sub(a.cacheLoaded) < remoteCacheTTL {
		if e, ok := a.remoteCache[name]; ok {
			a.mu.RUnlock()
			return e.remote, e.err
		}
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.cacheLoaded) >= remoteCacheTTL {
		// TTL истёк — перечитываем remotes. Двойная проверка после
		// захвата write-lock: конкурент мог уже обновить кеш.
		if err := a.reloadLocked(context.Background()); err != nil {
			// старый кеш лучше пустого: отдаём то, что есть
			if e, ok := a.remoteCache[name]; ok {
				return e.remote, e.err
			}
			return domain.Remote{}, err
		}
	}
	if e, ok := a.remoteCache[name]; ok {
		return e.remote, e.err
	}
	return domain.Remote{}, &domain.NotFoundError{What: "remote", Key: name}
}

// reloadLocked перечитывает Remotes из хранилища. mu уже захвачена
// на запись.
func (a *Adapter) reloadLocked(ctx context.Context) error {
	remotes, err := a.remotes.Remotes(ctx)
	a.cacheLoaded = a.clock.Now()
	if err != nil {
		return err
	}
	cache := make(map[string]remoteEntry, len(remotes))
	for _, r := range remotes {
		cache[r.Name] = remoteEntry{remote: r}
	}
	a.remoteCache = cache
	return nil
}

// splitRemotePath делит «<name>/<остальной-путь>» на имя remote и
// upstream-путь (с ведущим «/»). ok=false для traversal-попыток и
// пустого имени.
func splitRemotePath(rest string) (name, upstreamPath string, ok bool) {
	idx := strings.IndexByte(rest, '/')
	switch {
	case idx < 0:
		name, upstreamPath = rest, "/"
	default:
		name, upstreamPath = rest[:idx], rest[idx:]
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\/\x00") {
		return "", "", false
	}
	return name, upstreamPath, true
}

// compiledRule — скомпилированное правило классификации: регекс из
// glob + класс.
type compiledRule struct {
	re    *regexp.Regexp
	class domain.Class
	name  string
}

// rawRule — данные правила (glob + класс) до компиляции.
type rawRule struct {
	glob  string
	class domain.Class
}

// classifyRules — таблица классификации apt как данные: glob с
// поддержкой ** (любые сегменты), * (сегмент без /), ? (один байт без
// /). Порядок — от специфичного к общему; первый матч выигрывает.
func classifyRules() []rawRule {
	immutable := domain.Immutable()
	mutable := domain.Mutable(mutableIndexTTL)
	return []rawRule{
		// Immutable: пакеты и source-тарболы под pool/ (content-addressed).
		{"pool/**/*.deb", immutable},
		{"pool/**/*.udeb", immutable},
		{"pool/**/*.ddeb", immutable},
		{"pool/**/*.dsc", immutable},
		{"pool/**/*.orig.tar.*", immutable},
		{"pool/**/*.debian.tar.*", immutable},
		{"pool/**/*.tar.xz", immutable},
		{"pool/**/*.tar.gz", immutable},
		{"pool/**/*.tar.lzma", immutable},
		{"pool/**/*.tar.zst", immutable},
		// by-hash — content-addressed индексы, не меняются.
		{"**/by-hash/SHA*/*", immutable},
		{"**/by-hash/MD5*/*", immutable},
		// Mutable{TTL 5m}: индексы и подписи dists/.
		{"**/Release", mutable},
		{"**/Release.gpg", mutable},
		{"**/InRelease", mutable},
		{"**/Packages*", mutable},
		{"**/Sources*", mutable},
		{"**/Contents-*", mutable},
		{"**/i18n/*", mutable},
		{"**/dep11/*", mutable},
		{"**/cnf/Commands-*", mutable},
	}
}

// compileRules компилирует glob-правила в регексы один раз в New.
func compileRules() []compiledRule {
	raw := classifyRules()
	out := make([]compiledRule, len(raw))
	for i, r := range raw {
		out[i] = compiledRule{re: globToRegex(r.glob), class: r.class, name: r.glob}
	}
	return out
}

// globToRegex переводит glob в регекс: **/ → опциональный префикс
// каталогов, * → сегмент без /, ? → один байт без /. Literals
// эскейпятся.
func globToRegex(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(glob); {
		c := glob[i]
		switch {
		case c == '*' && i+1 < len(glob) && glob[i+1] == '*':
			if i+2 < len(glob) && glob[i+2] == '/' {
				// "**/" — любой префикс каталогов (включая пустой)
				b.WriteString(`(?:.*/)?`)
				i += 3
			} else {
				b.WriteString(".*")
				i += 2
			}
		case c == '*':
			b.WriteString(`[^/]*`)
			i++
		case c == '?':
			b.WriteString(`[^/]`)
			i++
		default:
			if strings.IndexByte(`\.+*?()|[]{}^$`, c) >= 0 {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
			i++
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String())
}
