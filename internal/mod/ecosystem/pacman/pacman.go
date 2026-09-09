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

// Package pacman — адаптер экосистемы Arch Linux (pacman): маппинг путей
// публичного порта /pacman/<remote>/<остальной-путь> на upstream и
// классификация объектов по изменчивости. Кеш RemoteStore с инвалидацией
// по TTL 30с (KISS): новые remotes подхватываются без рестарта.
// Streaming-парсер {repo}.db (tar.gz|tar.zst — авто-детект по magic →
// tar → desc) живёт в parse.go (переиспользуется зеркалом, сессия 11);
// декомпресс-лимит 1GiB — защита от zip-bomb.
//
// Имя экосистемы и URL-префикс совпадают: «pacman».
package pacman

import (
	"context"
	"errors"
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
const Name = "pacman"

// Периоды кеширования/ревалидации. remoteCacheTTL — TTL кеша RemoteStore
// (новые/изменённые remotes подхватываются без рестарта); TTL индексов
// mutable — инвариант экосистемы: pacman-базы меняются при каждом
// repo-add/repo-remove, подписи обязаны ревалидироваться вместе с ними.
// keys TTL 1h — публичные ключи репозитория меняются крайне редко,
// длинный TTL снижает обращения к upstream без риска протухания.
const (
	remoteCacheTTL    = 30 * time.Second
	mutableDBTTL      = 5 * time.Minute
	mutableKeysTTL    = 1 * time.Hour
	mutableUnknownTTL = 1 * time.Minute
)

// remoteReloadTimeout — шапка на DB-вызов reloadLocked под write-lock'ом:
// зависший каталог не держит hot-path дольше шапки. Дубль константы в
// каждом пакете легален — mod→mod импорты запрещены depguard'ом (по
// образцу writeAtomic сессии 40).
const remoteReloadTimeout = 5 * time.Second

func init() {
	registry.RegisterEcosystem(Name, func(_ config.Ecosystem, deps registry.EcosystemDeps) (port.Ecosystem, error) {
		return New(deps.Remotes, deps.Clock)
	})
}

// Adapter реализует port.Ecosystem для pacman.
type Adapter struct {
	remotes port.RemoteStore
	clock   port.Clock
	rules   []compiledRule

	mu            sync.RWMutex
	remoteCache   map[string]remoteEntry
	cacheLoaded   time.Time
	reloadTimeout time.Duration
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
		return nil, fmt.Errorf("pacman: RemoteStore обязателен")
	}
	if clock == nil {
		return nil, fmt.Errorf("pacman: Clock обязателен")
	}
	return &Adapter{
		remotes:       remotes,
		clock:         clock,
		rules:         compileRules(),
		remoteCache:   map[string]remoteEntry{},
		reloadTimeout: remoteReloadTimeout,
	}, nil
}

// Name возвращает имя экосистемы.
func (a *Adapter) Name() string { return Name }

// URLPrefix возвращает префикс путей публичного порта. У pacman
// префикс совпадает с именем.
func (a *Adapter) URLPrefix() string { return Name }

// Resolve переводит /pacman/<remote-name>/<остальной-путь> в Target.
// false — путь не принадлежит pacman или remote неизвестен/выключен.
// Кеш remotes обновляется по TTL 30с: перезапуск не нужен для вновь
// добавленных upstream'ов. UpstreamURL/UpstreamPath сохраняют оригинальный
// регистр (byte-exact к upstream); StorageKey лоуэркейсит путь
// сознательно: домен допускает регистр с сессии 19 (case-чувствительность
// закрыта отдельно в apt), но pacman-пути lowercase по конвенции
// формата, case-риск upstream признан низким.
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

// Classify делит объекты pacman по изменчивости. Пакеты (.pkg.tar.* и
// их .sig) — immutable (content-addressed по NEVRA в имени); репозитарные
// базы ({repo}.db, {repo}.files и их .sig, legacy .db.tar.* / .files.tar.*)
// — mutable{TTL 5m}; публичные ключи (keys/*) — mutable{TTL 1h}; прочее —
// conservative mutable{TTL 1m}. Пустой путь — ошибка валидации.
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

// Enumerate обходит .db каждого репозитория и собирает upstream-пути
// пакетов (поле %FILENAME% в desc-записи). Remote.Include для pacman —
// список репозиториев с архитектурой в форме «<repo>/<arch>» (например,
// «core/x86_64»): БД лежит по пути «<repo>/os/<arch>/<repo>.db», пакеты —
// «<repo>/os/<arch>/<filename>». Пустой Include — ошибка: pacman не имеет
// корневого индекса репозиториев, перечислить «вообще все» нельзя.
// Метаданные качаются через meta (движок кеша — singleflight/TTL/метрики).
//
// Чексуммы (не-цель v1): desc-запись upstream .db содержит %SHA256SUM%,
// но парсер (parse.go) извлекает только %FILENAME%/%NAME%/%VERSION% —
// таблица чексумм для Target.Checksum не наполняется, движок живёт
// сверкой Content-Length. Расширить ParseDesc — после первого
// практического кейса битого pacman-upstream.
func (a *Adapter) Enumerate(ctx context.Context, remote domain.Remote, meta port.MetaFetcher) ([]string, error) {
	if meta == nil {
		return nil, fmt.Errorf("pacman: Enumerate: MetaFetcher обязателен")
	}
	repos, err := parsePacmanInclude(remote.Include)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, r := range repos {
		got, err := a.enumerateRepo(ctx, meta, remote.Name, r)
		if err != nil {
			return nil, fmt.Errorf("pacman: enumerate %s/%s: %w", r.repo, r.arch, err)
		}
		for _, p := range got {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// pacmanRepo — распарсенный элемент Include: repo и arch.
type pacmanRepo struct {
	repo string
	arch string
}

// parsePacmanInclude разбирает Remote.Include на список репозиториев.
// Формат элемента: «<repo>/<arch>» (например, «core/x86_64»). Пустой
// Include — ошибка: pacman требует явного перечисления repo+arch.
func parsePacmanInclude(include []string) ([]pacmanRepo, error) {
	if len(include) == 0 {
		return nil, &domain.ValidationError{
			What: "include", Value: "", Reason: "pacman sync: укажите repo/arch (например [\"core/x86_64\"])",
		}
	}
	var out []pacmanRepo
	for _, item := range include {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		repo, arch, ok := strings.Cut(item, "/")
		if !ok || repo == "" || arch == "" {
			return nil, &domain.ValidationError{What: "include", Value: item, Reason: "ожидался формат «repo/arch»"}
		}
		if strings.ContainsAny(repo, " \x00") || strings.ContainsAny(arch, " \x00") {
			return nil, &domain.ValidationError{What: "include", Value: item, Reason: "repo/arch содержат недопустимые символы"}
		}
		out = append(out, pacmanRepo{repo: repo, arch: arch})
	}
	if len(out) == 0 {
		return nil, &domain.ValidationError{What: "include", Value: "", Reason: "нет валидных repo/arch"}
	}
	return out, nil
}

// enumerateRepo fetch'ит {repo}.db и достаёт %FILENAME% каждой записи.
// dbPath — «<repo>/os/<arch>/<repo>.db»; пакеты лежат рядом с db.
func (a *Adapter) enumerateRepo(ctx context.Context, meta port.MetaFetcher, remoteName string, r pacmanRepo) ([]string, error) {
	repoDir := r.repo + "/os/" + r.arch
	dbPath := "/" + Name + "/" + remoteName + "/" + repoDir + "/" + r.repo + ".db"
	body, err := meta.Fetch(ctx, dbPath)
	if err != nil {
		var nf *domain.NotFoundError
		if errors.As(err, &nf) {
			return nil, unsupportedDBErr(ctx, meta, dbPath, err)
		}
		return nil, err
	}
	defer body.Close()
	var paths []string
	for entry, perr := range ParseDB(body) {
		if perr != nil {
			return nil, fmt.Errorf("pacman: parse db: %w", perr)
		}
		fn := strings.TrimSpace(entry.Filename)
		if fn == "" {
			continue
		}
		paths = append(paths, "/"+repoDir+"/"+fn)
	}
	return paths, nil
}

// unsupportedDBErr — {repo}.db не найден. Пробуем legacy-имя
// {repo}.db.tar.gz (до zstd-эпохи Arch): если upstream публикует
// только его, sync должен падать с причиной «gzip не поддерживается»,
// а не с NotFound, неотличимым от пустого upstream (парсер .db
// читает только zstd — gz-декомпрессии нет). Иначе — исходный
// NotFound: индекс действительно отсутствует.
func unsupportedDBErr(ctx context.Context, meta port.MetaFetcher, dbPath string, notFound error) error {
	if body, err := meta.Fetch(ctx, dbPath+".tar.gz"); err == nil {
		_ = body.Close()
		return &domain.UnsupportedError{
			What: "enumerate",
			Why:  fmt.Sprintf("pacman: индекс %s.tar.gz в формате gzip — парсер читает только zstd (.db)", dbPath),
		}
	}
	return notFound
}

// lookupRemote возвращает Remote по имени из кеша; при истечении TTL
// перечитывает весь список remotes (KISS: remotes обычно единицы).
// Reload выполняется под write-lock'ом — простота двойной проверки без
// свапа снапшота; ограничение — таймаут DB-вызова (5s): зависшая БД
// задерживает hot-path лишь на шапку, а не навсегда. Вынос reload
// наружу со свапом — пост-v1: требует ревизии консистентности кеша
// между RLock/Lock-фазами.
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
		// захвата write-lock: конкурент мог уже обновить кеш. Шапка на
		// DB-вызов (см. выше); ошибка по таймауту не отличима от прочих
		// — «старый кеш лучше пустого» ниже обрабатывает её так же.
		ctx, cancel := context.WithTimeout(context.Background(), a.reloadTimeout)
		defer cancel()
		if err := a.reloadLocked(ctx); err != nil {
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
// пустого имени. Дубликат из apt/rpmmmd — mod→mod запрещён depguard'ом,
// держим адаптеры самодостаточными.
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
// регекс (для правил, неудобных как glob).
type rawRule struct {
	glob  string
	regex string
	class domain.Class
}

// classifyRules — таблица классификации pacman как данные. Порядок —
// от специфичного к общему; первый матч выигрывает.
func classifyRules() []rawRule {
	immutable := domain.Immutable()
	dbMutable := domain.Mutable(mutableDBTTL)
	keysMutable := domain.Mutable(mutableKeysTTL)
	return []rawRule{
		// Immutable: пакеты pacman (.pkg.tar.{zst,xz,gz}) и их подписи.
		// Content-addressed по NEVRA в имени файла.
		{"**/*.pkg.tar.zst", "", immutable},
		{"**/*.pkg.tar.xz", "", immutable},
		{"**/*.pkg.tar.gz", "", immutable},
		{"**/*.pkg.tar.zst.sig", "", immutable},
		{"**/*.pkg.tar.xz.sig", "", immutable},
		{"**/*.pkg.tar.gz.sig", "", immutable},
		// Mutable{TTL 5m}: репозитарные базы и их подписи. {repo}.db и
		// {repo}.files — современный формат; .db.tar.* / .files.tar.* —
		// legacy (repo-add без zstd). Базы перегенерируются при каждом
		// repo-add/repo-remove.
		{"", `^(?:.*/)?[^/]+\.db$`, dbMutable},
		{"", `^(?:.*/)?[^/]+\.files$`, dbMutable},
		{"", `^(?:.*/)?[^/]+\.db\.sig$`, dbMutable},
		{"", `^(?:.*/)?[^/]+\.files\.sig$`, dbMutable},
		{"", `^(?:.*/)?[^/]+\.db\.tar\.[^/]+$`, dbMutable},
		{"", `^(?:.*/)?[^/]+\.files\.tar\.[^/]+$`, dbMutable},
		// Mutable{TTL 1h}: публичные ключи репозитория (редко меняются).
		{"keys/*", "", keysMutable},
		// Прочее — conservative Mutable{TTL 1m} (безопасный дефолт).
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
// Дубликат из apt/rpmmmd: mod→mod запрещён, адаптеры самодостаточны.
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
