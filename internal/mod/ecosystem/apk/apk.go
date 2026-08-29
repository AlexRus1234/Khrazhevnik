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

// Package apk — адаптер экосистемы Alpine Linux (apk): маппинг путей
// публичного порта /apk/<remote>/<остальной-путь> на upstream и
// классификация объектов по изменчивости. Кеш RemoteStore с инвалидацией
// по TTL 30с (KISS): новые remotes подхватываются без рестарта.
// Streaming-парсер APKINDEX.tar.gz (gzip+tar → записи P:…) живёт в
// parse.go (переиспользуется зеркалом, сессия 11); декомпресс-лимит
// 1GiB — защита от zip-bomb.
//
// Имя экосистемы и URL-префикс совпадают: «apk».
package apk

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
const Name = "apk"

// Периоды кеширования/ревалидации. remoteCacheTTL — TTL кеша RemoteStore
// (новые/изменённые remotes подхватываются без рестарта); TTL индексов
// mutable — инвариант экосистемы: APKINDEX меняется при каждом
// apk-update репозитория, keys — редко (публичные ключи разработчиков
// Alpine), длинный TTL снижает обращения к upstream без риска.
const (
	remoteCacheTTL    = 30 * time.Second
	mutableIndexTTL   = 5 * time.Minute
	mutableKeysTTL    = 1 * time.Hour
	mutableUnknownTTL = 1 * time.Minute
)

func init() {
	registry.RegisterEcosystem(Name, func(_ config.Ecosystem, deps registry.EcosystemDeps) (port.Ecosystem, error) {
		return New(deps.Remotes, deps.Clock)
	})
}

// Adapter реализует port.Ecosystem для apk.
type Adapter struct {
	remotes port.RemoteStore
	clock   port.Clock
	rules   []compiledRule
	sums    *checksumIndex

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
		return nil, fmt.Errorf("apk: RemoteStore обязателен")
	}
	if clock == nil {
		return nil, fmt.Errorf("apk: Clock обязателен")
	}
	return &Adapter{
		remotes:     remotes,
		clock:       clock,
		rules:       compileRules(),
		sums:        newChecksumIndex(),
		remoteCache: map[string]remoteEntry{},
	}, nil
}

// Name возвращает имя экосистемы.
func (a *Adapter) Name() string { return Name }

// URLPrefix возвращает префикс путей публичного порта. У apk префикс
// совпадает с именем.
func (a *Adapter) URLPrefix() string { return Name }

// Resolve переводит /apk/<remote-name>/<остальной-путь> в Target.
// false — путь не принадлежит apk или remote неизвестен/выключен.
// Кеш remotes обновляется по TTL 30с: перезапуск не нужен для вновь
// добавленных upstream'ов. UpstreamURL/UpstreamPath сохраняют оригинальный
// регистр (byte-exact к upstream); StorageKey лоуэркейсит путь
// сознательно: домен допускает регистр с сессии 19 (case-чувствительность
// закрыта отдельно в apt), но apk-пути lowercase по конвенции
// формата, case-риск upstream признан низким. Checksum заполняется SHA1 из поля
// C: APKINDEX (если Enumerate уже разбирал индекс); без sync — честная
// деградация к Content-Length.
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
	target := port.Target{
		UpstreamURL:  base + upstreamPath,
		UpstreamPath: upstreamPath,
		StorageKey:   "cache/" + Name + "/" + strconv.FormatInt(remote.ID, 10) + strings.ToLower(upstreamPath),
	}
	if sum, ok := a.sums.lookup(remote.ID, upstreamPath); ok {
		target.Checksum = sum
	}
	return target, true
}

// Classify делит объекты apk по изменчивости. Пакеты (.apk) — immutable
// (content-addressed по имени с версией); APKINDEX.tar.gz (метаданные
// репозитория) — mutable{TTL 5m}; ключи (keys/*) — mutable{TTL 1h};
// прочее — conservative mutable{TTL 1m}. Пустой путь — ошибка валидации.
//
// apk v3 представляет APKINDEX.json — задел на будущее: классифицируем
// как mutable{TTL 5m}, как и tar.gz-вариант (когда Alpine стабилизирует
// формат, адаптер достанет его через тот же Enumerate).
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

// Enumerate обходит APKINDEX.tar.gz и собирает upstream-пути .apk
// пакетов (поле F: в записях APKINDEX — путь к пакету относительно корня
// репо, обычно «x86_64/foo-1.0-r0.apk»). Remote.Include для apk — список
// архитектур (например, «x86_64», «aarch64»); APKINDEX лежит по пути
// «<arch>/APKINDEX.tar.gz». Пустой Include — ошибка: apk не имеет
// корневого индекса архитектур, перечислить «вообще все» нельзя.
// Метаданные качаются через meta (движок кеша — singleflight/TTL/метрики).
//
// Побочный эффект — наполнение таблицы чексумм remote из поля C:
// записей (SHA1 пакета): после успешного sync прокси-ветка сверяет
// скачанные .apk с индексом.
func (a *Adapter) Enumerate(ctx context.Context, remote domain.Remote, meta port.MetaFetcher) ([]string, error) {
	if meta == nil {
		return nil, fmt.Errorf("apk: Enumerate: MetaFetcher обязателен")
	}
	archs, err := parseApkInclude(remote.Include)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	sums := make(map[string]port.Checksum)
	var paths []string
	for _, arch := range archs {
		got, err := a.enumerateArch(ctx, meta, remote.Name, arch, seen, sums)
		if err != nil {
			return nil, fmt.Errorf("apk: enumerate %s: %w", arch, err)
		}
		for _, p := range got {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}
	// Только после полного прохода: частичный sync не должен оставлять
	// таблицу, «знающую» меньше, чем прежняя.
	a.sums.replace(remote.ID, sums)
	return paths, nil
}

// parseApkInclude разбирает Remote.Include на список архитектур. Формат
// элемента — просто имя архитектуры («x86_64», «aarch64»). Пустой
// Include — ошибка: apk требует явного перечисления архитектур.
func parseApkInclude(include []string) ([]string, error) {
	if len(include) == 0 {
		return nil, &domain.ValidationError{
			What: "include", Value: "", Reason: "apk sync: укажите архитектуры (например [\"x86_64\"])",
		}
	}
	var out []string
	for _, item := range include {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.ContainsAny(item, " \x00/") {
			return nil, &domain.ValidationError{What: "include", Value: item, Reason: "архитектура содержит недопустимые символы"}
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, &domain.ValidationError{What: "include", Value: "", Reason: "нет валидных архитектур"}
	}
	return out, nil
}

// enumerateArch fetch'ит <arch>/APKINDEX.tar.gz и достаёт поле F: каждой
// записи (и C: — для таблицы чексумм). Путь пакета в APKINDEX —
// относительный от корня репо (Alpine кладёт пакеты в pool/<arch>/ или
// прямо в <arch>/; APKINDEX хранит полный относительный путь в F:).
func (a *Adapter) enumerateArch(ctx context.Context, meta port.MetaFetcher, remoteName, arch string, seen map[string]struct{}, sums map[string]port.Checksum) ([]string, error) {
	indexRel := arch + "/APKINDEX.tar.gz"
	indexEcoPath := "/" + Name + "/" + remoteName + "/" + indexRel
	body, err := meta.Fetch(ctx, indexEcoPath)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var paths []string
	for entry, perr := range ParseAPKINDEX(body) {
		if perr != nil {
			return nil, fmt.Errorf("apk: parse apkindex: %w", perr)
		}
		p := strings.TrimSpace(entry.FilePath)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if _, ok := seen[p]; !ok {
			if sum, ok := csumFromIndex(entry.Checksum); ok {
				sums[p] = sum
			}
		}
		paths = append(paths, p)
	}
	return paths, nil
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
// пустого имени. Дубликат из apt/rpmmmd/pacman — mod→mod запрещён
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

// classifyRules — таблица классификации apk как данные. Порядок —
// от специфичного к общему; первый матч выигрывает.
func classifyRules() []rawRule {
	immutable := domain.Immutable()
	indexMutable := domain.Mutable(mutableIndexTTL)
	keysMutable := domain.Mutable(mutableKeysTTL)
	return []rawRule{
		// Immutable: .apk пакеты (content-addressed по имени+версии).
		{"**/*.apk", "", immutable},
		// Mutable{TTL 5m}: APKINDEX — индекс репозитория, меняется при
		// каждом apk-update. tar.gz — текущий формат (v2/v3); .json —
		// задел для apk v3 (когда Alpine стабилизирует формат).
		{"**/APKINDEX.tar.gz", "", indexMutable},
		{"**/APKINDEX.json", "", indexMutable},
		// подписи индекса (если репо подписано).
		{"**/APKINDEX.tar.gz.sig", "", indexMutable},
		{"**/APKINDEX.json.sig", "", indexMutable},
		// Mutable{TTL 1h}: публичные ключи разработчиков Alpine (редко
		// меняются). Метаданные подписи репо ссылаются на эти ключи.
		{"keys/*", "", keysMutable},
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
// Дубликат из apt/rpmmmd/pacman: mod→mod запрещён, адаптеры самодостаточны.
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
