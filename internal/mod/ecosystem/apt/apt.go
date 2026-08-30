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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
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

	// maxDecompressedApt — лимит на разжатый Packages.gz-поток
	// (zip-bomb guard, инвариант сессии 12 — общий с pacman/apk).
	maxDecompressedApt = int64(1 << 30) // 1 GiB
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
	sums    *checksumIndex

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
		sums:        newChecksumIndex(),
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
// добавленных upstream'ов. Регистр сохраняется во всех трёх полях
// (byte-exact к upstream): StorageKey допускает верхний регистр после
// расширения charset в domain.ValidateKey — лоуэркейс склеивал бы
// /pool/Foo.deb и /pool/foo.deb в один ключ кеша, и второй клиент
// получал бы байты первого (poisoning на case-чувствительном upstream).
// Checksum заполняется, если Enumerate (sync зеркала) уже разбирал
// Packages с SHA256 этого пути; без sync чексумм нет — движок честно
// деградирует к Content-Length.
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
		StorageKey:   "cache/" + Name + "/" + strconv.FormatInt(remote.ID, 10) + upstreamPath,
	}
	if sum, ok := a.sums.lookup(remote.ID, upstreamPath); ok {
		target.Checksum = sum
	}
	return target, true
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

// Enumerate обходит метаданные apt-репозитория и собирает upstream-пути
// пакетов (поле Filename в Packages). Remote.Include задаёт dists и
// опционально компоненты: «stable» (все компоненты из Release) или
// «stable/main» (только main). Пустой Include — ошибка: apt не имеет
// корневого индекса dists, перечислить «вообще все» нельзя. Метаданные
// качаются через meta (движок кеша — singleflight/TTL/метрики).
// Архитектура «all» не используется для выбора Packages-файлов: пакеты
// Architecture: all перечислены в каждом binary-<arch>/Packages, так
// что дедуп по Filename убирает повторы.
//
// Побочный эффект — наполнение таблицы чексумм remote из поля SHA256
// stanza: после успешного sync прокси-ветка сверяет скачанные .deb с
// индексом (checksum-index живёт до следующего Enumerate).
func (a *Adapter) Enumerate(ctx context.Context, remote domain.Remote, meta port.MetaFetcher) ([]string, error) {
	if meta == nil {
		return nil, fmt.Errorf("apt: Enumerate: MetaFetcher обязателен")
	}
	dists, componentsByDist, err := parseAptInclude(remote.Include)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	sums := make(map[string]port.Checksum)
	var paths []string
	for _, dist := range dists {
		comps, archs, err := a.releaseComponents(ctx, meta, remote.Name, dist)
		if err != nil {
			return nil, fmt.Errorf("apt: enumerate dist %s: %w", dist, err)
		}
		allowed := componentsByDist[dist]
		for _, comp := range comps {
			if len(allowed) > 0 && !allowed[comp] {
				continue
			}
			for _, arch := range archs {
				if arch == "all" {
					continue
				}
				got, err := a.enumeratePackages(ctx, meta, remote.Name, dist, comp, arch, seen, sums)
				if err != nil {
					return nil, fmt.Errorf("apt: enumerate %s/%s/%s: %w", dist, comp, arch, err)
				}
				paths = append(paths, got...)
			}
		}
	}
	// Только после полного прохода: частичный sync не должен оставлять
	// таблицу, «знающую» меньше, чем прежняя.
	a.sums.replace(remote.ID, sums)
	return paths, nil
}

// parseAptInclude разбирает Remote.Include на множество dists и
// отображение dist → set разрешённых компонент. «stable» — все
// компоненты из Release (set пустой = нет фильтра); «stable/main» —
// только main. Пустой Include — ошибка.
func parseAptInclude(include []string) (dists []string, componentsByDist map[string]map[string]bool, err error) {
	if len(include) == 0 {
		return nil, nil, &domain.ValidationError{
			What: "include", Value: "", Reason: "apt sync: укажите dists (например [\"stable\"] или [\"stable/main\"])",
		}
	}
	componentsByDist = map[string]map[string]bool{}
	seenDist := map[string]bool{}
	for _, item := range include {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		dist, comp, ok := strings.Cut(item, "/")
		if !ok {
			dist, comp = item, ""
		}
		if dist == "" || strings.ContainsAny(dist, " \x00") {
			return nil, nil, &domain.ValidationError{What: "include", Value: item, Reason: "пустой или некорректный dist"}
		}
		if !seenDist[dist] {
			seenDist[dist] = true
			dists = append(dists, dist)
		}
		if comp != "" {
			set, ok := componentsByDist[dist]
			if !ok {
				set = map[string]bool{}
				componentsByDist[dist] = set
			}
			set[comp] = true
		}
	}
	if len(dists) == 0 {
		return nil, nil, &domain.ValidationError{What: "include", Value: "", Reason: "нет валидных dists"}
	}
	return dists, componentsByDist, nil
}

// releaseComponents fetch'ит Release dist и возвращает списки
// Components и Architectures (пробел-разделённые поля).
func (a *Adapter) releaseComponents(ctx context.Context, meta port.MetaFetcher, remoteName, dist string) ([]string, []string, error) {
	ecoPath := "/" + Name + "/" + remoteName + "/dists/" + dist + "/Release"
	body, err := meta.Fetch(ctx, ecoPath)
	if err != nil {
		return nil, nil, err
	}
	defer body.Close()
	var comps, archs []string
	for s, ferr := range Stanzas(body) {
		if ferr != nil {
			return nil, nil, ferr
		}
		comps = strings.Fields(s.Get("Components"))
		archs = strings.Fields(s.Get("Architectures"))
		// Release — одна stanza; выходим после первой.
		break
	}
	if len(comps) == 0 {
		return nil, nil, fmt.Errorf("Release без Components")
	}
	if len(archs) == 0 {
		return nil, nil, fmt.Errorf("Release без Architectures")
	}
	return comps, archs, nil
}

// enumeratePackages fetch'ит Packages-файл компонента/арха и достаёт
// поле Filename каждой записи (и SHA256 — для таблицы чексумм).
// Пробует несжатый Packages, затем .gz (Debian часто отдаёт только
// сжатый), затем честную ошибку для .xz-only upstream'а. Дедуп по
// seen (перезаписи «all»-пакетов в разных arch-файлах).
func (a *Adapter) enumeratePackages(ctx context.Context, meta port.MetaFetcher, remoteName, dist, comp, arch string, seen map[string]struct{}, sums map[string]port.Checksum) ([]string, error) {
	base := "/" + Name + "/" + remoteName + "/dists/" + dist + "/" + comp + "/binary-" + arch + "/Packages"
	body, err := meta.Fetch(ctx, base)
	if err != nil {
		var nf *domain.NotFoundError
		if errors.As(err, &nf) {
			body, err = meta.Fetch(ctx, base+".gz")
			if err != nil {
				if nfGz := (*domain.NotFoundError)(nil); errors.As(err, &nfGz) {
					return nil, unsupportedIndexErr(ctx, meta, base, err)
				}
				return nil, err
			}
			defer body.Close()
			gz, gzErr := gzip.NewReader(body)
			if gzErr != nil {
				return nil, fmt.Errorf("unpack Packages.gz: %w", gzErr)
			}
			defer func() { _ = gz.Close() }()
			// Декомпресс-лимит (аудит 2026-08-30): злонамеренный upstream
			// с gzip-бомбой вместо Packages.gz не должен съесть память
			// процесса — лимит проверяется в процессе чтения (по образцу
			// pacman/apk).
			limited := &limitedReader{r: gz, limit: maxDecompressedApt}
			return scanFilenames(limited, seen, sums)
		}
		return nil, err
	}
	defer body.Close()
	return scanFilenames(body, seen, sums)
}

// unsupportedIndexErr — Packages нет ни несжатым, ни в .gz. Debian/
// Ubuntu публикуют ещё и .xz: если upstream отдаёт только его, sync
// должен падать с причиной «формат не поддерживается», а не с
// NotFound, неотличимым от пустого upstream (xz-декодера в whitelist
// зависимостей нет и не добавляем). Если .xz тоже нет — исходный
// NotFound: индекс действительно отсутствует.
func unsupportedIndexErr(ctx context.Context, meta port.MetaFetcher, base string, notFound error) error {
	if body, err := meta.Fetch(ctx, base+".xz"); err == nil {
		_ = body.Close()
		return &domain.UnsupportedError{
			What: "enumerate",
			Why:  fmt.Sprintf("apt: индекс %s.xz в неподдерживаемом формате xz — декодера нет в whitelist зависимостей", base),
		}
	}
	return notFound
}

// scanFilenames читает Packages-поток и собирает уникальные Filename
// (+SHA256 stanza в sums — первое вхождение выигрывает, как и в seen).
func scanFilenames(r io.Reader, seen map[string]struct{}, sums map[string]port.Checksum) ([]string, error) {
	var out []string
	for s, err := range Stanzas(r) {
		if err != nil {
			return nil, err
		}
		fn := strings.TrimSpace(s.Get("Filename"))
		if fn == "" {
			continue
		}
		if !strings.HasPrefix(fn, "/") {
			fn = "/" + fn
		}
		if _, ok := seen[fn]; ok {
			continue
		}
		seen[fn] = struct{}{}
		if sum, ok := hexChecksum("sha256", s.Get("SHA256")); ok {
			sums[fn] = sum
		}
		out = append(out, fn)
	}
	return out, nil
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

// ErrDecompressTooLarge — разжатый Packages.gz превысил лимит
// (zip-bomb guard). Сравнение через errors.Is.
var ErrDecompressTooLarge = errors.New("apt: декомпрессия превысила лимит")

// limitedReader — обёртка, считающая байты и возвращающая
// ErrDecompressTooLarge при превышении лимита (паттерн pacman/apk):
// лимит проверяется в процессе чтения, а не после полного буфера.
type limitedReader struct {
	r     io.Reader
	n     int64
	limit int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n >= l.limit {
		return 0, ErrDecompressTooLarge
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.limit {
		return n, ErrDecompressTooLarge
	}
	return n, err
}
