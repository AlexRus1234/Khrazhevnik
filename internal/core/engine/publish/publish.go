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

// Package publish — движок личных репозиториев: upload пакетов по
// scoped-токенам/владельцем, квоты, immutable-ключи, генерация
// индексов через port.RepoAdapter. Не знает форматов пакетов — только
// делегирует адаптеру экосистемы. Подпись InRelease/Release.gpg —
// сессия 15; атомарный swap — сессия 17 (с s3).
package publish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strconv"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Config — параметры движка publish. MaxObjectSize — лимит одного
// объекта; 0 → без лимита (на свой риск; квота всё равно считается).
type Config struct {
	MaxObjectSize int64
}

// Engine — движок личных репозиториев. Потокобезопасный: состояние —
// в storage/repos и в per-key in-flight-карте upload'ов (см.
// acquireInFlight); прочих in-memory кешей нет.
type Engine struct {
	storage  port.Storage
	repos    port.RepoStore
	clock    port.Clock
	adapters map[string]port.RepoAdapter
	cfg      Config
	// inFlight — ключи, upload которых идёт прямо сейчас. Закрытое
	// состояние движка, защищено inFlightMu (не package-level var).
	inFlightMu sync.Mutex
	inFlight   map[string]struct{}
}

// New создаёт движок. nil clock → системная реализация (как у mirror);
// nil adapters → движок работает без генератора (reindex → Unsupported).
func New(cfg Config, storage port.Storage, repos port.RepoStore, clock port.Clock, adapters map[string]port.RepoAdapter) *Engine {
	if clock == nil {
		clock = systemClock{}
	}
	if adapters == nil {
		adapters = map[string]port.RepoAdapter{}
	}
	if cfg.MaxObjectSize < 0 {
		cfg.MaxObjectSize = 0
	}
	return &Engine{storage: storage, repos: repos, clock: clock, adapters: adapters, cfg: cfg, inFlight: map[string]struct{}{}}
}

// Upload стримит объект в репозиторий. path — путь внутри репо
// (apt: pool/main/f/foo.deb); ключ хранилища = repo/<id>/<eco>/<path>.
// size — заявленный Content-Length; body обязан отдать ровно size байт.
// force=true игнорирует конфликт существующего ключа (только админ
// вызывает; движок не знает роли — это контракт вызова).
//
// Проверки (по порядку): domain.ValidateKey → adapter.ValidateObjectPath
// → MaxObjectSize → per-key in-flight (параллельный upload того же
// ключа — 409) → существующий ключ (409 conflict, кроме force) → квота
// (Storage.List репо-префикса; при force-перезаписи старый размер
// вычитается). Запись — транзакционная: недокачка или перелимит →
// Abort, tmp чист. Квота перепроверяется по фактическому размеру тела
// ПОСЛЕ загрузки в tmp, ДО Commit.
func (e *Engine) Upload(ctx context.Context, repo domain.Repo, path string, size int64, body io.Reader, force bool) error {
	adapter, err := e.adapter(repo)
	if err != nil {
		return err
	}
	key, err := e.keyFor(repo, path)
	if err != nil {
		return err
	}
	if err := adapter.ValidateObjectPath(path); err != nil {
		return err
	}
	if e.cfg.MaxObjectSize > 0 && size > e.cfg.MaxObjectSize {
		return &domain.TooLargeError{Size: size, Limit: e.cfg.MaxObjectSize}
	}
	// Сериализация per-key: без неё два параллельных upload одного
	// ключа оба проходили бы «объекта нет» и оба коммитили (TOCTOU
	// Stat→Put) — тихая взаимная перезапись вместо ConflictError.
	if err := e.acquireInFlight(key); err != nil {
		return err
	}
	defer e.releaseInFlight(key)
	oldSize, exists, err := e.statExisting(ctx, key)
	if err != nil {
		return err
	}
	if exists && !force {
		return &domain.ConflictError{What: "объект", Key: key, Reason: "уже загружен; force=true перезапишет (только админ)"}
	}
	if err := e.checkQuota(ctx, repo, size, exists, oldSize); err != nil {
		return err
	}
	w, err := e.storage.Put(ctx, key)
	if err != nil {
		return err
	}
	n, err := e.copyBody(w, body, size)
	if err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	// Повторная проверка квоты по фактическому размеру (заявленный
	// Content-Length мог солгать): сужает гонку двух upload РАЗНЫХ
	// ключей до окна tmp→Commit (v1-граница: строгая квота требует
	// учёта в БД — не-цель).
	if err := e.checkQuota(ctx, repo, n, exists, oldSize); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	return nil
}

// Delete удаляет объект из репозитория. Отсутствующий — NotFound.
// Метаданные, сгенерированные reindex, не трогает (они перегенерируются).
func (e *Engine) Delete(ctx context.Context, repo domain.Repo, path string) error {
	if _, err := e.adapter(repo); err != nil {
		return err
	}
	key, err := e.keyFor(repo, path)
	if err != nil {
		return err
	}
	return e.storage.Delete(ctx, key)
}

// List возвращает метаданные объектов репо (по префиксу repo/<id>/).
// Порядок — лексический (как у Storage.List). Ошибка листинга —
// терминальная: (Meta{}, err), после неё выдаётся только err. Срез
// генерируется потребителем полностью; для репо с тысячами объектов
// это десятки КБ — KISS v1.
func (e *Engine) List(ctx context.Context, repo domain.Repo) iter.Seq2[port.Meta, error] {
	prefix := "repo/" + strconv.FormatInt(repo.ID, 10) + "/"
	return e.storage.List(ctx, prefix)
}

// Reindex запускает генерацию индексов через RepoAdapter. Прогресс
// передаётся адаптеру (как у mirror); подпись и atomic-swap — сессии
// 15/17. Адаптер ведёт обход и запись сам, движок только делегирует.
func (e *Engine) Reindex(ctx context.Context, repo domain.Repo, p Progress) error {
	adapter, err := e.adapter(repo)
	if err != nil {
		return err
	}
	if p == nil {
		p = noopProgress{}
	}
	return adapter.GenerateIndexes(ctx, repo, e.storage, repoProgressAdapter{p: p})
}

// Progress — репортёр прогресса фоновой задачи publish (reindex). Не
// знает о TaskRegistry — только о кадрах прогресса и логах, как
// mirror.Progress. Склейка с web.Progress идёт в wire.
type Progress interface {
	Update(phase, current string, processed, total int64)
	Log(line string)
}

// noopProgress — заглушка, чтобы Reindex можно было звать без репортёра.
type noopProgress struct{}

func (noopProgress) Update(string, string, int64, int64) {}
func (noopProgress) Log(string)                          {}

// repoProgressAdapter переводит publish.Progress → port.RepoProgress:
// сигнатуры идентичны, но типы разные (порт не должен импортировать
// engine; обратное — тоже).
type repoProgressAdapter struct{ p Progress }

func (a repoProgressAdapter) Update(phase, current string, processed, total int64) {
	a.p.Update(phase, current, processed, total)
}
func (a repoProgressAdapter) Log(line string) { a.p.Log(line) }

// adapter возвращает RepoAdapter экосистемы репо или UnsupportedError.
func (e *Engine) adapter(repo domain.Repo) (port.RepoAdapter, error) {
	if a, ok := e.adapters[repo.Ecosystem]; ok {
		return a, nil
	}
	return nil, &domain.UnsupportedError{What: "publish", Why: "экосистема " + repo.Ecosystem + " не имеет генератора индексов (адаптер не зарегистрирован)"}
}

// keyFor строит ключ хранения: repo/<id>/<eco>/<path>. Path проходит
// domain.ValidateKey — единая точка path-traversal (ValidateObjectPath
// адаптера дополнительная, экосистемная).
func (e *Engine) keyFor(repo domain.Repo, path string) (string, error) {
	key := "repo/" + strconv.FormatInt(repo.ID, 10) + "/" + repo.Ecosystem + "/" + path
	if err := domain.ValidateKey(key); err != nil {
		return "", err
	}
	return key, nil
}

// statExisting выясняет, существует ли ключ, и возвращает его размер
// (квоте нужен вычет при force-перезаписи). Ошибка носителя — fail-
// closed: она не должна выглядеть как «объекта нет», иначе проверка
// конфликта и подсчёт квоты солгали бы одновременно.
func (e *Engine) statExisting(ctx context.Context, key string) (int64, bool, error) {
	meta, err := e.storage.Stat(ctx, key)
	if err != nil {
		var nf *domain.NotFoundError
		if errors.As(err, &nf) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("publish: stat %s: %w", key, err)
	}
	return meta.Size, true, nil
}

// acquireInFlight помечает ключ «загрузка идёт»: второй параллельный
// upload того же ключа получает ConflictError (перожидание сделало бы
// горутину заложником чужого клиента — при обрыве он всё равно узнает
// 409 и повторит). Граница между инстансами — документирована: v1
// рассчитан на один инстанс (строго — учёт в БД, не-цель).
func (e *Engine) acquireInFlight(key string) error {
	e.inFlightMu.Lock()
	defer e.inFlightMu.Unlock()
	if _, busy := e.inFlight[key]; busy {
		return &domain.ConflictError{What: "upload", Key: key, Reason: "загрузка этого ключа уже идёт; повторите после её завершения"}
	}
	e.inFlight[key] = struct{}{}
	return nil
}

// releaseInFlight снимает метку per-key in-flight (defer в Upload).
func (e *Engine) releaseInFlight(key string) {
	e.inFlightMu.Lock()
	defer e.inFlightMu.Unlock()
	delete(e.inFlight, key)
}

// checkQuota считает сумму размеров и число объектов репо через
// Storage.List и сравнивает с Quota (ноль = без лимита). size —
// заявленный (до копирования) или фактический (повторная проверка
// перед Commit) размер нового объекта. При force-перезаписи
// (replacing=true) старый размер объекта вычитается из usedBytes, а
// число объектов не растёт: без вычета старый размер складывался бы с
// новым — двойной счёт и ложный отказ. Ошибка листинга или stat —
// ошибка upload (fail-closed): молчаливый «пустой» обход занизил бы
// used и пропустил бы перелимит. KISS v1: List-обход на каждой из двух
// проверок; для больших репо (s3 без List-обхода) — таблица
// repo_objects в сессии 17.
func (e *Engine) checkQuota(ctx context.Context, repo domain.Repo, size int64, replacing bool, oldSize int64) error {
	if repo.Quota.MaxBytes == 0 && repo.Quota.MaxObjects == 0 {
		return nil
	}
	var usedBytes, usedFiles int64
	prefix := "repo/" + strconv.FormatInt(repo.ID, 10) + "/"
	for meta, err := range e.storage.List(ctx, prefix) {
		if err != nil {
			return fmt.Errorf("publish: листинг квоты repo %d: %w", repo.ID, err)
		}
		usedBytes += meta.Size
		usedFiles++
	}
	byteDelta, objDelta := size, int64(1)
	if replacing {
		byteDelta = size - oldSize
		objDelta = 0
	}
	if repo.Quota.MaxBytes > 0 && usedBytes+byteDelta > repo.Quota.MaxBytes {
		return &domain.QuotaExceededError{RepoID: repo.ID, Used: usedBytes + byteDelta, Limit: repo.Quota.MaxBytes}
	}
	if repo.Quota.MaxObjects > 0 && usedFiles+objDelta > repo.Quota.MaxObjects {
		return &domain.QuotaExceededError{RepoID: repo.ID, Used: usedFiles + objDelta, Limit: repo.Quota.MaxObjects}
	}
	return nil
}

// copyBody стримит body в writer с проверкой: лимит на лету (если есть)
// и сверка с заявленным size. Несовпадение → TooLarge/Upstream-обёртка.
func (e *Engine) copyBody(w port.Writer, body io.Reader, size int64) (int64, error) {
	src := body
	if e.cfg.MaxObjectSize > 0 {
		src = io.LimitReader(body, e.cfg.MaxObjectSize+1)
	}
	n, err := io.Copy(w, src)
	if err != nil {
		return n, fmt.Errorf("publish: чтение тела: %w", err)
	}
	if e.cfg.MaxObjectSize > 0 && n > e.cfg.MaxObjectSize {
		return n, &domain.TooLargeError{Size: n, Limit: e.cfg.MaxObjectSize}
	}
	if size >= 0 && n != size {
		return n, &domain.ValidationError{What: "size", Value: strconv.FormatInt(n, 10), Reason: "Content-Length " + strconv.FormatInt(size, 10) + " не совпал с фактическим размером " + strconv.FormatInt(n, 10)}
	}
	return n, nil
}

// systemClock — port.Clock поверх time.Now (как у mirror; тесты
// подменяют через testutil).
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
