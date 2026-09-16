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

// Package storagegc — консервативная выметающая чистка объектов
// хранилища: осиротевшие версии mutable-объектов кеша (сбой фонового
// удаления, cache/engine.go) и остатки удалённых личных репозиториев
// (repo/<id>/). Консервативность важнее полноты: ложное срабатывание
// удаляет ЖИВОЙ объект, а неполнота закрывается следующим проходом
// (ROADMAP, ограничение M4-Р5). Отдельный компонент рядом с движком
// (прецедент statskeeper/Scheduler) — движок кеша не расширяется и не
// получает порта каталога; горутин жизненного цикла у Sweeper нет,
// воркеры и админ-задачи зовут Sweep синхронно.
package storagegc

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Префиксы корней единого namespace хранения (прецедент s3-sweep:
// листинг только своих корней, чужое не трогаем).
const (
	cachePrefix = "cache/"
	repoPrefix  = "repo/"
)

// deleteConcurrency — потолок одновременных удалений (образец delSem
// кеша, cache/engine.go): параллельные проходы не должны выметать
// носитель всплеском.
const deleteConcurrency = 4

// Result — итоги одного прохода. Каждый объект cache/ и repo/ попадает
// ровно в один из счётчиков scanned; orphan'ы считаются и в dry-run
// (иначе ревизия перед чисткой бессмысленна). Duration — время прохода
// (для гистограммы метрик), измеряется часами Sweeper'а.
type Result struct {
	DryRun        bool
	Duration      time.Duration
	CacheScanned  int64
	CacheOrphans  int64
	RepoScanned   int64
	RepoOrphans   int64
	Deleted       int64
	FailedDeletes int64
	BytesFreed    int64
}

// Sweeper — выметающая чистка хранилища. Новый проход — вызов Sweep;
// состояние прохода локально, между вызовами не переносится.
type Sweeper struct {
	storage port.Storage
	index   port.ObjectIndex
	repos   port.RepoStore
	clock   port.Clock
	grace   time.Duration
	re      *regexp.Regexp
	sem     chan struct{}

	// OnSweep — хук метрик после каждого прохода (nil-safe), наполнение
	// — в wire (сессия 120); ошибка прохода передаётся как есть.
	OnSweep func(res Result, err error)
	// OnError — колбэк ошибок периодического тика Run (инжектится wire'ом,
	// как Scheduler.ErrorHook): сбой прохода не гасит цикл, но и не
	// теряется молча. Ручные вызовы наверх ошибку возвращают сами.
	OnError func(error)

	// mu охраняет cancel/done — поля жизненного цикла Run/Stop.
	mu     sync.Mutex
	cancel context.CancelFunc // nil до Run и после Stop
	done   chan struct{}      // закрытие = горутина-тикер вышла
}

// New собирает sweeper. grace — минимальный возраст кандидата по
// ModTime; дефолт задаёт конфиг (сессия 120), движок принимает любое
// значение ≥0 (0 — тестам и явной админской чистке).
func New(storage port.Storage, index port.ObjectIndex, repos port.RepoStore, clock port.Clock, grace time.Duration) *Sweeper {
	if grace < 0 {
		grace = 0
	}
	return &Sweeper{
		storage: storage,
		index:   index,
		repos:   repos,
		clock:   clock,
		grace:   grace,
		// Суффикс версии mutable-ключа (cache/engine.go versionedKey):
		// "-v" + base36 nonce запуска (UnixNano, ≥12 знаков) + base36
		// seq (≥1). Порог 11 — запас снизу от реальных ≥13.
		re:  regexp.MustCompile(`-v[0-9a-z]{11,}$`),
		sem: make(chan struct{}, deleteConcurrency),
	}
}

// Sweep — один проход по cache/ и repo/. dryRun считает кандидатов,
// ничего не удаляя. Ошибка индекса/каталога или листинга — fail-closed:
// «не удалось перечислить» никогда не маскируется под «объектов нет».
func (s *Sweeper) Sweep(ctx context.Context, dryRun bool) (Result, error) {
	start := s.clock.Now()
	res := Result{DryRun: dryRun}
	err := s.sweep(ctx, &res, dryRun)
	res.Duration = s.clock.Now().Sub(start)
	return s.report(res, err)
}

// SweepRepoPrefix выметает всё под repo/<id>/ — точечная чистка после
// удаления репозитория (сессия 122). Без dry-run: смысл вызова —
// освободить префикс, который больше не принадлежит живому репо.
func (s *Sweeper) SweepRepoPrefix(ctx context.Context, repoID int64) (Result, error) {
	start := s.clock.Now()
	var res Result
	err := s.sweepRepoPrefix(ctx, &res, repoID)
	res.Duration = s.clock.Now().Sub(start)
	return s.report(res, err)
}

// report вызывает хук и отдаёт итог прохода наружу.
func (s *Sweeper) report(res Result, err error) (Result, error) {
	if s.OnSweep != nil {
		s.OnSweep(res, err)
	}
	return res, err
}

// sweep строит референс-наборы (живые storage_key и id репозиториев) и
// прогоняет оба корня.
func (s *Sweeper) sweep(ctx context.Context, res *Result, dryRun bool) error {
	live := make(map[string]struct{})
	byKey := make(map[string]domain.ObjectMeta)
	if err := s.index.ForEachObjectMeta(ctx, func(m domain.ObjectMeta) error {
		byKey[m.Key] = m
		if m.StorageKey != "" {
			live[m.StorageKey] = struct{}{}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("storagegc: обход индекса объектов: %w", err)
	}
	repoList, err := s.repos.Repos(ctx)
	if err != nil {
		return fmt.Errorf("storagegc: список репозиториев: %w", err)
	}
	repoIDs := make(map[int64]struct{}, len(repoList))
	for _, r := range repoList {
		repoIDs[r.ID] = struct{}{}
	}
	now := s.clock.Now()
	if err := s.sweepCache(ctx, res, live, byKey, now, dryRun); err != nil {
		return err
	}
	return s.sweepRepos(ctx, res, repoIDs, dryRun)
}

// sweepCache обходит cache/ консервативными правилами кандидата.
func (s *Sweeper) sweepCache(ctx context.Context, res *Result, live map[string]struct{}, byKey map[string]domain.ObjectMeta, now time.Time, dryRun bool) error {
	for meta, err := range s.storage.List(ctx, cachePrefix) {
		if err != nil {
			return fmt.Errorf("storagegc: листинг %s: %w", cachePrefix, err)
		}
		if ctx.Err() != nil {
			break
		}
		res.CacheScanned++
		if !s.cacheOrphan(meta, live, byKey, now) {
			continue
		}
		res.CacheOrphans++
		if !dryRun {
			s.deleteKey(ctx, meta.Key, meta.Size, res)
		}
	}
	return ctx.Err()
}

// cacheOrphan — тройное правило кандидата. Пропуск осторожен: лучше
// оставить осиротевший объект до следующего прохода, чем удалить
// живой.
func (s *Sweeper) cacheOrphan(meta port.Meta, live map[string]struct{}, byKey map[string]domain.ObjectMeta, now time.Time) bool {
	// (a) storage_key живого объекта — не трогать.
	if _, ok := live[meta.Key]; ok {
		return false
	}
	// (b) нет версионного суффикса — immutable (строк БД не имеет) или
	// чужой ключ, защищённый формой.
	loc := s.re.FindStringIndex(meta.Key)
	if loc == nil {
		return false
	}
	// (c) строка логического ключа обязана существовать и указывать на
	// другую версию; нет строки — «чужое имя»/удалённый объект (пропуск
	// сознательный). Равенство storage_key самому ключу уже отсёк live.
	if _, ok := byKey[meta.Key[:loc[0]]]; !ok {
		return false
	}
	// (d) объект старше now−grace (grace=0 — строго старше now).
	return meta.ModTime.Before(now.Add(-s.grace))
}

// sweepRepos выметает объекты репозиториев, чьих строк нет в каталоге.
func (s *Sweeper) sweepRepos(ctx context.Context, res *Result, repoIDs map[int64]struct{}, dryRun bool) error {
	for meta, err := range s.storage.List(ctx, repoPrefix) {
		if err != nil {
			return fmt.Errorf("storagegc: листинг %s: %w", repoPrefix, err)
		}
		if ctx.Err() != nil {
			break
		}
		res.RepoScanned++
		// Ключи личных репо не версионированы (publish.keyFor): сегмент
		// после префикса — id; нечисловой сегмент — чужой namespace.
		seg, _, _ := strings.Cut(strings.TrimPrefix(meta.Key, repoPrefix), "/")
		id, perr := strconv.ParseInt(seg, 10, 64)
		if perr != nil {
			continue
		}
		if _, ok := repoIDs[id]; ok {
			// Строка репо создаётся до первого upload — grace не нужен.
			continue
		}
		res.RepoOrphans++
		if !dryRun {
			s.deleteKey(ctx, meta.Key, meta.Size, res)
		}
	}
	return ctx.Err()
}

// sweepRepoPrefix — всё под repo/<id>/ (сессия 122).
func (s *Sweeper) sweepRepoPrefix(ctx context.Context, res *Result, repoID int64) error {
	prefix := repoPrefix + strconv.FormatInt(repoID, 10) + "/"
	for meta, err := range s.storage.List(ctx, prefix) {
		if err != nil {
			return fmt.Errorf("storagegc: листинг %s: %w", prefix, err)
		}
		if ctx.Err() != nil {
			break
		}
		res.RepoScanned++
		res.RepoOrphans++
		s.deleteKey(ctx, meta.Key, meta.Size, res)
	}
	return ctx.Err()
}

// deleteKey удаляет один объект. NotFound — «уже нет» (гонка с другим
// удалением), не сбой; прочие ошибки копятся в FailedDeletes, проход
// продолжается. Семафор живёт на Sweeper: параллельные проходы делят
// потолок удалений.
func (s *Sweeper) deleteKey(ctx context.Context, key string, size int64, res *Result) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	if err := s.storage.Delete(ctx, key); err != nil {
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

// Run запускает горутину-тикер периодической чистки: раз в interval —
// Sweep(ctx, false). Тикер — time.Ticker, а не port.Clock: момент
// снятия времени не важен, часы Sweeper'а нужны лишь домену (grace,
// Duration). Отличие от statskeeper.Run: тик идёт в runCtx БЕЗ
// WithoutCancel — обход хранилища длинный, отмена между ключами зашита
// в Sweep (сессия 119), и shutdown не должен ждать целого прохода
// ради короткого флаша, как у статистики. Ошибка тика — в OnError,
// цикл продолжает тикать. interval <= 0 недопустим (time.Ticker
// паникует) — его отсекает wire.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if _, err := s.Sweep(runCtx, false); err != nil && s.OnError != nil {
					s.OnError(err)
				}
			}
		}
	}()
}

// Stop гасит тикер и ждёт выхода горутины. Финального прохода НЕТ, в
// отличие от финального флаша statskeeper: чистка не теряет данные
// (остаток подберёт следующий запуск), а полный обход хранилища на
// выходе растянул бы бюджет shutdown. Повторный Stop идемпотентен.
func (s *Sweeper) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
