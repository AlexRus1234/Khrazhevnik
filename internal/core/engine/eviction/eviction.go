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

// Package eviction — авто-очистка старого кеша pull-through прокси (волна
// «Eviction кеш-прокси»). Отдельный компонент рядом с retention: проход
// идёт по одному remote и переиспользует контракт движка ретеншна
// (Result/Report), чтобы API/GUI (202/203) взяли готовую механику один в
// один. Горутин жизненного цикла у движка нет (прецедент storagegc):
// раннер и админ-задачи зовут Apply синхронно.
//
// Консервативность важнее полноты: ложное срабатывание удаляет живой
// объект, а неполнота закрывается следующим проходом. Критерий удаления
// двухусловный (решение владельца 2026-10-03): у семейства больше
// MinVersions живых версий И к кандидату не обращались дольше MaxAgeDays.
// Версия жива, если она в топ-N семейства по ModTime ИЛИ обращение к ней
// свежее now−MaxAgeDays; защиты складываются по ИЛИ, «живых версий»
// считает та же топ-N-гарантия (кандидат существует только когда семейство
// шире минимума).
//
// Отличия от ретеншна личных репо (три, зафиксированы при планировании):
//
//	(а) proxy-only — зеркало не чистится: зеркало это полная копия
//	    upstream, и churn «скачал → удалил → скачал» конфликтует с
//	    resume-diff sync. Инвариант держит сам движок (раннер 201
//	    фильтрует режимы раньше, но API-триггер 202 зовёт Apply напрямую);
//	(б) без reindex — у кеша его нет: индексы кеша это метаданные
//	    upstream (побайтовый инвариант MISS↔HIT), перегенерировать нечего;
//	(в) без пинов — пин-хранилище личных репо (repo_pins) кеша не
//	    касается: счётчик ProtectedByPin не переносится.
//
// Семейства резолвит адаптер экосистемы (port.CacheFamilyResolver) по
// upstream-пути объекта — движок не знает форматов имён; индексы, подписи
// и служебные объекты резолвер отдаёт как ok=false (это и есть запрет
// «mutable-объекты кеша — не кандидаты никогда»). Упорядочивание версий —
// по ModTime, НЕ по разбору версий: важна свежесть загрузки.
package eviction

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

const (
	// deleteConcurrency — потолок одновременных удалений (образец delSem
	// кеша, retention и storagegc): проход не должен выметать носитель
	// всплеском.
	deleteConcurrency = 4

	// cacheRoot — корень namespace кеша-прокси в едином хранилище (тот же
	// литерал у storagegc). Префикс листинга одного remote —
	// cache/<eco>/<remote-id>/ — строится от него и Remote.ID ровно так
	// же, как адаптеры собирают StorageKey (apt.go:152 и твины).
	cacheRoot = "cache/"

	// retainedMarker — marker by-hash-поколений apt-генератора
	// (gen.go:80, читается readRetainedHashes): имя служебного объекта
	// под by-hash/. В cache/ такой объект не появляется — marker пишет
	// генератор личного репо (repo/<id>/apt/...), с upstream он не
	// приходит; фильтр оставлен как защита на будущее/для repo-формы,
	// а не как наблюдаемое явление (см. постамбулу сессии 200).
	retainedMarker = ".retained"
)

// versionedRe — суффикс версии mutable-ключа кеша (cache/engine.go
// versionedKey: key + "-v" + base36 nonce запуска + base36 seq). Порог 11
// — тот же запас снизу, что у storagegc (gc.go:113: nonce ≥12 знаков
// base36): форма обязана совпадать с фильтром выметающей чистки, чтобы
// два места не расходились. Прошлые версии mutable-объектов чистит
// storagegc — eviction их только не трогает.
var versionedRe = regexp.MustCompile(`-v[0-9a-z]{11,}$`)

// Result — итоги одного прохода. Счётчики защит диагностические: версия
// попадает ровно в один из них (первая сработавшая защита), а жива она при
// любой из двух — защиты складываются по ИЛИ. Duration — время прохода
// (для гистограммы метрик, сессия 201), измеряется часами движка — образец
// storagegc.Result/retention.Result.
type Result struct {
	DryRun            bool
	Duration          time.Duration
	Families          int64
	ObjectsScanned    int64
	Candidates        int64
	Deleted           int64
	FailedDeletes     int64
	BytesFreed        int64
	ProtectedByMin    int64
	ProtectedByAccess int64
}

// Report — строка отчёта Preview (сессия 202: прогноз чистки в GUI и API):
// версия семейства, прошедшая топ-N-фильтр, и причина, по которой она
// уцелела. ProtectedBy пуст у настоящего кандидата на удаление, «access» —
// свежее обращение. Версии, защищённые топ-N, в отчёт не входят: их считает
// Result.ProtectedByMin (отчёт — про то, что политика рассматривает, а не
// про весь кеш).
type Report struct {
	Key         string
	Family      string
	Size        int64
	ModTime     time.Time
	LastAccess  time.Time
	ProtectedBy string
}

// version — объект семейства в рамках прохода: ключ, размер и дата
// загрузки (ModTime носителя).
type version struct {
	key     string
	size    int64
	modTime time.Time
}

// Engine — один проход по кешу одного remote. Новый проход — вызов Apply;
// состояние прохода локально, между вызовами не переносится.
type Engine struct {
	storage  port.Storage
	access   port.AccessStore
	adapters map[string]port.RepoAdapter
	clock    port.Clock
	def      domain.Retention
	sem      chan struct{}

	// OnApply — хук после каждого прохода (nil-safe), наполнение — в
	// сессии 201 (метрики); ошибка прохода передаётся как есть.
	OnApply func(res Result, err error)
}

// New собирает движок eviction. adapters — карта адаптеров экосистем из
// wire (тот же набор, что у publish/retention): семейство кеш-путей
// резолвит генератор экосистемы (port.CacheFamilyResolver), отсутствие
// резолвера — честная ошибка прохода, а не молчаливый no-op. def —
// глобальный дефолт политики из конфига [eviction] ({0,0} — выключено).
func New(storage port.Storage, access port.AccessStore, adapters map[string]port.RepoAdapter, clock port.Clock, def domain.Retention) *Engine {
	return &Engine{
		storage:  storage,
		access:   access,
		adapters: adapters,
		clock:    clock,
		def:      def,
		sem:      make(chan struct{}, deleteConcurrency),
	}
}

// Policy — эффективная политика remote, tri-state (Remote.Eviction):
// указатель задан — политика remote как есть (&Retention{0,0} — «явно
// выключено»), nil — наследование глобального дефолта (def {0,0} —
// выключено). Тот же доступ нужен раннеру (201) и API (202) — поэтому
// метод экспортирован.
func (e *Engine) Policy(remote domain.Remote) domain.Retention {
	if remote.Eviction != nil {
		return *remote.Eviction
	}
	return e.def
}

// Apply — один проход по кешу remote. dryRun считает кандидатов, ничего не
// удаляя (ревизия перед чисткой). Политика выключена — no-op без ошибки
// (кеш растёт в пределах носителя). Возвращаемая ошибка — сбой прохода
// (листинг, состояние обращений, отмена), а не «нечего удалять»; частично
// выполненные удаления остаются выполненными.
func (e *Engine) Apply(ctx context.Context, remote domain.Remote, dryRun bool) (Result, error) {
	res := Result{DryRun: dryRun}
	start := e.clock.Now()
	err := e.apply(ctx, &res, remote, dryRun, nil)
	res.Duration = e.clock.Now().Sub(start)
	if e.OnApply != nil {
		e.OnApply(res, err)
	}
	return res, err
}

// Preview — сухой проход с отчётом по версиям: тот же разбор защит, что у
// Apply(dryRun=true), плюс строка Report на каждую рассмотренную версию
// (причина защиты или пусто — кандидат). Носитель не меняется: удалений в
// dry-run нет по построению. Хук OnApply не зовётся — прогноз инициирует
// пользователь, это не проход политики: метрика проходов искажалась бы
// ручными прогнозами (образец retention.Preview, сессия 171).
func (e *Engine) Preview(ctx context.Context, remote domain.Remote) (Result, []Report, error) {
	res := Result{DryRun: true}
	start := e.clock.Now()
	var reports []Report
	err := e.apply(ctx, &res, remote, true, &reports)
	res.Duration = e.clock.Now().Sub(start)
	return res, reports, err
}

// apply — тело прохода: политика → резолвер → листинг с группировкой по
// семействам → разбор каждого семейства. reports != nil — наполняется
// строками отчёта (Preview); nil — проход без деталей (Apply).
func (e *Engine) apply(ctx context.Context, res *Result, remote domain.Remote, dryRun bool, reports *[]Report) error {
	policy := e.Policy(remote)
	if !policy.Enabled() {
		return nil
	}
	// proxy-only: детали — в doc-комментарии пакета (отличие «а»).
	if remote.Mode == domain.ModeMirror {
		return nil
	}
	resolver, err := e.familyResolver(remote)
	if err != nil {
		return err
	}
	// Листинг — только кеш этого remote: keyPrefix (без «/») отрезается
	// от storage-ключа, отдавая резолверу upstream-путь с ведущим «/»
	// (форма Target.UpstreamPath); listPrefix — граница листинга, чтобы
	// сосед по номеру (remote 1 vs 12) не подмешался.
	keyPrefix := cacheRoot + remote.Ecosystem + "/" + strconv.FormatInt(remote.ID, 10)
	listPrefix := keyPrefix + "/"
	families := make(map[string][]version)
	var order []string
	for meta, lerr := range e.storage.List(ctx, listPrefix) {
		if lerr != nil {
			return fmt.Errorf("eviction: листинг %s: %w", listPrefix, lerr)
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		res.ObjectsScanned++
		path := strings.TrimPrefix(meta.Key, keyPrefix)
		// Прошлые версии mutable-объектов (их чистит storagegc) и
		// marker by-hash-поколений — не кандидаты никогда.
		if versionedRe.MatchString(path) || isRetainedMarker(path) {
			continue
		}
		// Резолвер получает upstream-путь; ok=false — индексы, подписи,
		// служебные файлы: eviction их не трогает (живут upstream'ом).
		family, ok := resolver.CacheObjectFamily(path)
		if !ok {
			continue
		}
		if _, seen := families[family]; !seen {
			order = append(order, family)
		}
		families[family] = append(families[family], version{key: meta.Key, size: meta.Size, modTime: meta.ModTime})
	}
	now := e.clock.Now()
	for _, family := range order {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		res.Families++
		if err := e.sweepFamily(ctx, res, family, families[family], policy, now, dryRun, reports); err != nil {
			return err
		}
	}
	return nil
}

// isRetainedMarker — служебный marker by-hash (корень или basename пути).
func isRetainedMarker(path string) bool {
	p := strings.TrimPrefix(path, "/")
	return p == retainedMarker || strings.HasSuffix(p, "/"+retainedMarker)
}

// familyResolver достаёт резолвер семейств кеш-путей у генератора
// экосистемы. Отсутствие адаптера или резолвера — честный UnsupportedError,
// а не «объектов нет»: движок не знает, что чистить, и молчаливый no-op
// скрыл бы неработающую чистку (у nix семейств нет — content-addressed,
// старых версий одного пути не бывает).
func (e *Engine) familyResolver(remote domain.Remote) (port.CacheFamilyResolver, error) {
	adapter, ok := e.adapters[remote.Ecosystem]
	if !ok || adapter == nil {
		return nil, &domain.UnsupportedError{
			What: "eviction",
			Why:  "нет адаптера экосистемы " + remote.Ecosystem,
		}
	}
	resolver, ok := adapter.(port.CacheFamilyResolver)
	if !ok {
		return nil, &domain.UnsupportedError{
			What: "eviction",
			Why:  "экосистема " + remote.Ecosystem + " не резолвит семейства кеш-путей (nix — content-addressed)",
		}
	}
	return resolver, nil
}

// sweepFamily разбирает одно семейство: топ-N защищён, остальных решает
// давность обращения, второй условие критерия — гарантия минимума.
// Возвращает ошибку только если состояние обращений прочесть нельзя:
// гадать о давности и удалять «наугад» запрещено — fail-closed, как у
// листинга.
func (e *Engine) sweepFamily(ctx context.Context, res *Result, family string, versions []version, policy domain.Retention, now time.Time, dryRun bool, reports *[]Report) error {
	// Свежие — последние по ModTime; тай-брейк по ключу делает топ-N
	// детерминированным при совпадении времени (пакетный upload).
	slices.SortFunc(versions, func(a, b version) int {
		if c := b.modTime.Compare(a.modTime); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	top := policy.MinVersions
	if top > len(versions) {
		top = len(versions)
	}
	// Максимум возраста: MaxAgeDays == 0 — ограничения нет (только keep-N),
	// отрицательный отсекает валидация политики.
	cutoff := time.Time{}
	if policy.MaxAgeDays > 0 {
		cutoff = now.Add(-time.Duration(policy.MaxAgeDays) * 24 * time.Hour)
	}
	for i, v := range versions {
		if i < top {
			res.ProtectedByMin++
			continue
		}
		// Бутстрап last-access: нет строки обращений — дата загрузки
		// (решение владельца: обращений не было, считаем от ModTime).
		lastAccess := v.modTime
		var nf *domain.NotFoundError
		entry, err := e.access.AccessEntry(ctx, domain.AccessScopeCache, v.key)
		switch {
		case err == nil:
			lastAccess = entry.LastAccess
		case errors.As(err, &nf):
			// Обращений не было — считаем от даты загрузки.
		default:
			return fmt.Errorf("eviction: обращение к %s: %w", v.key, err)
		}
		// Причина защиты фиксируется первой сработавшей (как и счётчики):
		// отчёт показывает, что именно спасло версию, а не полный разбор.
		protectedBy := ""
		if !cutoff.IsZero() && !lastAccess.Before(cutoff) {
			res.ProtectedByAccess++
			protectedBy = "access"
		} else {
			res.Candidates++
		}
		if reports != nil {
			*reports = append(*reports, Report{
				Key: v.key, Family: family, Size: v.size,
				ModTime: v.modTime, LastAccess: lastAccess, ProtectedBy: protectedBy,
			})
		}
		// Удаляем только настоящего кандидата и только в боевом проходе.
		if protectedBy == "" && !dryRun {
			e.deleteKey(ctx, v.key, v.size, res)
		}
	}
	return nil
}

// deleteKey удаляет одну версию. NotFound — «уже нет» (гонка с другим
// удалением или с самим собой после сбоя), не сбой; прочие ошибки копятся в
// FailedDeletes, проход продолжается (следующий запуск доберёт). Семафор
// живёт на движке: параллельные проходы делят потолок удалений.
func (e *Engine) deleteKey(ctx context.Context, key string, size int64, res *Result) {
	e.sem <- struct{}{}
	defer func() { <-e.sem }()
	if err := e.storage.Delete(ctx, key); err != nil {
		var nf *domain.NotFoundError
		if errors.As(err, &nf) {
			return
		}
		res.FailedDeletes++
		return
	}
	res.Deleted++
	res.BytesFreed += size
}
