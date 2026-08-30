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

// Package nix — адаптер экосистемы nix binary cache: маппинг путей
// публичного порта /nix/<remote>/<остальной-путь> на upstream и
// классификация объектов по изменчивости. Контент адресован (nar и
// narinfo зовутся 32-символьным хешем store path) — идеальный
// immutable-кеш; поддерживаем только pull-through (полное зеркало
// cache.nixos.org — десятки ТБ, не цель). Кеш RemoteStore с
// инвалидацией по TTL 30с (KISS): новые remotes подхватываются без
// рестарта.
//
// Инвариант nix: narinfo содержит URL: nar/… и Sig: <key>:… — НЕ
// переписываем, отдаём побайтово (подписи остаются валидными, если
// клиент доверяет ключу upstream). Классификация только по пути:
// nar/<32 nix-base32>.nar.xz|.nar — immutable (навсегда); <32 nix-
// base32>.narinfo — mutable{TTL 1h} (маленький, byte-exact, реиспоуз
// и патчи путей невозможны); nix-cache-info — mutable{TTL 1h};
// log/<…> — immutable.
//
// 404 на narinfo — штатная ситуация nix-клиента (перебор
// substituter'ов): negative-cache движка кеша (сессия 06) уже
// отдаёт корректный 404 (не 502) и быстро.
//
// Имя экосистемы и URL-префикс совпадают: «nix».
package nix

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
const Name = "nix"

// Периоды кеширования/ревалидации. remoteCacheTTL — TTL кеша RemoteStore
// (новые/изменённые remotes подхватываются без рестарта); TTL narinfo и
// nix-cache-info — инвариант экосистемы: narinfo маленький и byte-exact
// (реиспоуз и патчи путей невозможны), длинный TTL снижает обращения к
// upstream; nix-cache-info меняется редко (метаданные кеша upstream).
// nar-файлы и log-объекты — immutable (content-addressed по хешу).
const (
	remoteCacheTTL      = 30 * time.Second
	mutableNarinfoTTL   = 1 * time.Hour
	mutableCacheInfoTTL = 1 * time.Hour
	mutableUnknownTTL   = 1 * time.Minute
)

func init() {
	registry.RegisterEcosystem(Name, func(_ config.Ecosystem, deps registry.EcosystemDeps) (port.Ecosystem, error) {
		return New(deps.Remotes, deps.Clock)
	})
}

// Adapter реализует port.Ecosystem для nix.
type Adapter struct {
	remotes port.RemoteStore
	clock   port.Clock
	rules   []compiledRule

	mu          sync.RWMutex
	remoteCache map[string]remoteEntry
	cacheLoaded time.Time
}

// remoteEntry — кеш одной записи RemoteStore по имени: remote и момент
// обновления. err кешируется тоже (БД легла — не долбим её каждым
// запросом, пока TTL не вышел).
type remoteEntry struct {
	remote domain.Remote
	err    error
}

// New создаёт адаптер: remotes — источник upstream-конфигураций, clock —
// время для инвалидации кеша remotes. Правила классификации компилируются
// один раз.
func New(remotes port.RemoteStore, clock port.Clock) (*Adapter, error) {
	if remotes == nil {
		return nil, fmt.Errorf("nix: RemoteStore обязателен")
	}
	if clock == nil {
		return nil, fmt.Errorf("nix: Clock обязателен")
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

// URLPrefix возвращает префикс путей публичного порта. У nix префикс
// совпадает с именем.
func (a *Adapter) URLPrefix() string { return Name }

// Resolve переводит /nix/<remote-name>/<остальной-путь> в Target.
// false — путь не принадлежит nix или remote неизвестен/выключен.
// Кеш remotes обновляется по TTL 30с: перезапуск не нужен для вновь
// добавленных upstream'ов. UpstreamURL/UpstreamPath сохраняют оригинальный
// регистр (byte-exact к upstream); StorageKey лоуэркейсит путь — доменный
// ключ допускает только [a-z0-9/._-].
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

// Classify делит объекты nix binary cache по изменчивости. nar-файлы
// (nar/<32 nix-base32>.nar.xz|.nar) и log/<…> — immutable
// (content-addressed, кешируются навсегда); <32 nix-base32>.narinfo —
// mutable{TTL 1h} (маленький, byte-exact, подписи upstream валидны);
// nix-cache-info — mutable{TTL 1h}; прочее — conservative
// mutable{TTL 1m}. Пустой путь — ошибка валидации.
//
// Хеш store path валидируется как 32 символа nix-base32
// ([0123456789abcdfghijklmnpqrsvwxyz]{32} — канонический алфавит nix,
// libutil/hash.cc, без e/o/t/u): так кодирует хеши реальный nix, и
// именно такой хеш допускает upload в личные репо (publish.go).
// Ранний контракт (сессия 13) требовал 32 hex — реальные narinfo/nar
// не матчились и падали в conservative mutable{TTL 1m} (реиспейс
// каждую минуту вместо immutable-кеша).
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

// Enumerate — синк всего upstream для nix binary cache не реализуем:
// cache.nixos.org — десятки ТБ, перечислять «вообще всё» нельзя.
// Только pull-through «по использованию»: narinfo (запрошенный клиентом)
// → nar через WantNar (parse.go) — задел для будущего префетча
// (сессия 16 не требует; функция есть, интеграции нет).
func (a *Adapter) Enumerate(context.Context, domain.Remote, port.MetaFetcher) ([]string, error) {
	return nil, &domain.UnsupportedError{
		What: "enumerate",
		Why:  "nix: синк всего cache.nixos.org не реализуем (десятки ТБ) — только pull-through «по использованию»",
	}
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

// reloadLocked перечитывает Remotes из хранилища. mu уже захвачена на запись.
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
// пустого имени. Дубликат из apt/rpmmmd/pacman/apk — mod→mod запрещён
// depguard'ом, держим адаптеры самодостаточными.
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

// compiledRule — скомпилированное правило классификации: регекс + класс.
type compiledRule struct {
	re    *regexp.Regexp
	class domain.Class
	name  string
}

// rawRule — данные правила до компиляции. glob непуст — паттерн
// переводится через globToRegex; regex непуст — используется как сырой
// регекс.
type rawRule struct {
	glob  string
	regex string
	class domain.Class
}

// classifyRules — таблица классификации nix как данные. Порядок —
// от специфичного к общему; первый матч выигрывает. nar/narinfo
// валидируют 32-символьный nix-base32 хеш store path регексом
// (content-addressed; алфавит nix — без e/o/t/u).
func classifyRules() []rawRule {
	immutable := domain.Immutable()
	narinfoMutable := domain.Mutable(mutableNarinfoTTL)
	cacheInfoMutable := domain.Mutable(mutableCacheInfoTTL)
	return []rawRule{
		// Immutable: nar-архивы (content-addressed по хешу store path).
		// nar.xz — сжатый (основной формат); nar — несжатый (редко).
		{"", `^nar/[0123456789abcdfghijklmnpqrsvwxyz]{32}\.nar\.xz$`, immutable},
		{"", `^nar/[0123456789abcdfghijklmnpqrsvwxyz]{32}\.nar$`, immutable},
		// Mutable{TTL 1h}: narinfo — метаданные пути (маленький, byte-exact,
		// подписи upstream валидны). Реиспоуз и патчи путей невозможны.
		{"", `^[0123456789abcdfghijklmnpqrsvwxyz]{32}\.narinfo$`, narinfoMutable},
		// Mutable{TTL 1h}: nix-cache-info — метаданные кеша upstream
		// (StoreDir, WantMassQuery, priority). Меняется редко.
		{"nix-cache-info", "", cacheInfoMutable},
		// Immutable: log/<…> — логи сборки, адресованы хешем store path.
		{"log/**", "", immutable},
		// Прочее — conservative Mutable{TTL 1m}.
	}
}

// compileRules компилирует правила один раз в New.
func compileRules() []compiledRule {
	raw := classifyRules()
	out := make([]compiledRule, len(raw))
	for i, r := range raw {
		var re *regexp.Regexp
		switch {
		case r.regex != "":
			re = regexp.MustCompile(r.regex)
			out[i] = compiledRule{re: re, class: r.class, name: r.regex}
		default:
			re = globToRegex(r.glob)
			out[i] = compiledRule{re: re, class: r.class, name: r.glob}
		}
	}
	return out
}

// globToRegex переводит glob в регекс: **/ → опциональный префикс
// каталогов, * → сегмент без /, ? → один байт без /. Literals эскейпятся.
// Дубликат из apt/rpmmmd/pacman/apk: mod→mod запрещён, адаптеры самодостаточны.
func globToRegex(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(glob); {
		c := glob[i]
		switch {
		case c == '*' && i+1 < len(glob) && glob[i+1] == '*':
			if i+2 < len(glob) && glob[i+2] == '/' {
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
