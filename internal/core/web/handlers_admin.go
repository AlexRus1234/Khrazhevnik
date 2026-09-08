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

// Тонкие хендлеры админ-API: парс → порт/usecase → writeJSON/writeErr.
// Маппинг domain-ошибок на HTTP — централизован в statusFor (validate.go).
// Хендлеры не решают коды ответов сами, кроме случаев, где ошибки нет
// (404 по URL-параметру). Аудит мутаций — автоматический middleware
// (audit.go), хендлеры могут дописать detail/action через WithAudit*.

package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
)

// remoteOut — DTO ответа remote: ID и поля без аудиторских мусора.
// Include нормализуется в пустой срез, чтобы JSON был [], а не null
// (SPA рендерит список без nil-проверок).
type remoteOut struct {
	ID           int64             `json:"id"`
	Name         string            `json:"name"`
	Ecosystem    string            `json:"ecosystem"`
	BaseURL      string            `json:"base_url"`
	Mode         domain.RemoteMode `json:"mode"`
	Enabled      bool              `json:"enabled"`
	SyncInterval time.Duration     `json:"sync_interval"`
	Include      []string          `json:"include"`
	CreatedAt    time.Time         `json:"created_at"`
}

// remoteOutFrom модели → DTO.
func remoteOutFrom(r domain.Remote) remoteOut {
	include := r.Include
	if include == nil {
		include = []string{}
	}
	return remoteOut{
		ID: r.ID, Name: r.Name, Ecosystem: r.Ecosystem, BaseURL: r.BaseURL,
		Mode: r.Mode, Enabled: r.Enabled, Include: include,
		SyncInterval: r.SyncInterval, CreatedAt: r.CreatedAt,
	}
}

// handleListRemotes — GET /api/v1/remotes: список upstream'ов.
func handleListRemotes(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rs, err := d.Remotes.Remotes(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]remoteOut, 0, len(rs))
		for _, rem := range rs {
			out = append(out, remoteOutFrom(rem))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleCreateRemote — POST /api/v1/remotes: создать upstream.
func handleCreateRemote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in remoteInput
		if !decodeJSON(w, r, &in) {
			return
		}
		if err := in.validate(); err != nil {
			writeErr(w, err)
			return
		}
		enabled := true
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		// Action ставится ДО вызова каталога (паттерн user.create,
		// сессия 63): отклонённая мутация иначе писалась бы middleware
		// под fallback-именем метода+пути (create.remotes), а успешная —
		// под remote.create; два имени одной операции ломали трейл.
		*r = *r.WithContext(WithAuditAction(r.Context(), "remote.create"))
		rem, err := d.Remotes.CreateRemote(r.Context(), domain.Remote{
			Name: in.Name, Ecosystem: in.Ecosystem, BaseURL: in.BaseURL,
			Mode: domain.RemoteMode(in.Mode), Enabled: enabled, Include: in.Include,
			SyncInterval: in.SyncInterval,
			CreatedAt:    d.clock().Now(),
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		d.notifyRemotesChanged()
		writeJSON(w, http.StatusCreated, remoteOutFrom(rem))
	}
}

// handleUpdateRemote — PATCH /api/v1/remotes/{id}: частичное
// обновление. Реализовано как full-replace: клиент должен прислать все
// поля, которые он хочет сохранить (SPA так и делает); пустые поля
// станут нулями. Это упрощает контракт и не плодит partial-update
// транзакций.
func handleUpdateRemote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		existing, err := d.Remotes.Remote(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		var in remoteInput
		if !decodeJSON(w, r, &in) {
			return
		}
		if err := in.validate(); err != nil {
			writeErr(w, err)
			return
		}
		enabled := existing.Enabled
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		updated := domain.Remote{
			ID: existing.ID, Name: in.Name, Ecosystem: in.Ecosystem,
			BaseURL: in.BaseURL, Mode: domain.RemoteMode(in.Mode),
			Enabled: enabled, Include: in.Include, SyncInterval: in.SyncInterval,
			CreatedAt: existing.CreatedAt,
		}
		// Action до каталога — как в handleCreateRemote: единое имя
		// remote.update для middleware-записи при любом исходе.
		*r = *r.WithContext(WithAuditAction(r.Context(), "remote.update"))
		if err := d.Remotes.UpdateRemote(r.Context(), updated); err != nil {
			writeErr(w, err)
			return
		}
		d.notifyRemotesChanged()
		writeJSON(w, http.StatusOK, remoteOutFrom(updated))
	}
}

// handleDeleteRemote — DELETE /api/v1/remotes/{id}.
func handleDeleteRemote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		// Action до каталога — как в handleCreateRemote: единое имя
		// remote.delete для middleware-записи при любом исходе.
		*r = *r.WithContext(WithAuditAction(r.Context(), "remote.delete"))
		if err := d.Remotes.DeleteRemote(r.Context(), id); err != nil {
			writeErr(w, err)
			return
		}
		d.notifyRemotesChanged()
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleSyncRemote — POST /api/v1/remotes/{id}/sync → 202 + task-id.
// Запускает mirror.Sync через TaskRegistry: реальный sync-воркер
// (enumerate → diff → worker pool prefetch) с прогрессом в sync_jobs.
// Дублирующий sync того же remote — 409 (TaskRegistry активный ключ
// «sync|<name>»); превышение пула воркеров — 429.
func handleSyncRemote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Tasks == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "tasks_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		if d.Mirror == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "mirror_unavailable")
			return
		}
		// Action до движка (паттерн сессии 63): 409 дубликата и 429
		// лимита записываются под remote.sync, а не fallback-именем.
		*r = *r.WithContext(WithAuditAction(r.Context(), "remote.sync"))
		taskID, err := d.Mirror.Sync(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		d.notifyRemotesChanged()
		writeJSON(w, http.StatusAccepted, map[string]string{"task_id": taskID})
	}
}

// notifyRemotesChanged дёргает планировщик зеркал (если собран):
// reconcile увидит новый/изменённый/удалённый remote на ближайшем
// цикле, не дожидаясь тика.
func (d Deps) notifyRemotesChanged() {
	if d.OnRemotesChanged != nil {
		d.OnRemotesChanged()
	}
}

// handleListTasks — GET /api/v1/tasks: снимки всех задач.
func handleListTasks(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Tasks == nil {
			writeJSON(w, http.StatusOK, []TaskSnapshot{})
			return
		}
		writeJSON(w, http.StatusOK, d.Tasks.Snapshots())
	}
}

// handleGetTask — GET /api/v1/tasks/{id}: снимок одной задачи. Контракт
// api.md — 200/404: и неизвестный id, и Tasks==nil (деградация без
// реестра) → 404. От расхождение со списком (200 [] при Tasks==nil)
// сознательно отказались в пользу api.md: «пусто» честно для списка,
// но конкретный id без реестра не существует (аудит 2026-08-30,
// сессия 45).
func handleGetTask(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Tasks == nil {
			writeErrCode(w, http.StatusNotFound, "not_found")
			return
		}
		id := chi.URLParam(r, "id")
		task, ok := d.Tasks.Get(id)
		if !ok {
			writeErrCode(w, http.StatusNotFound, "not_found")
			return
		}
		writeJSON(w, http.StatusOK, task.Snapshot())
	}
}

// ecoStatsOut — per-eco ряд статистики кеша (сессия 92): те же поля,
// что и глобал, плюс имя экосистемы и свой hit_ratio.
type ecoStatsOut struct {
	Ecosystem         string  `json:"ecosystem"`
	Hits              int64   `json:"hits"`
	Misses            int64   `json:"misses"`
	HitRatio          float64 `json:"hit_ratio"`
	StaleServed       int64   `json:"stale_served"`
	NegativeHits      int64   `json:"negative_hits"`
	UpstreamErrors    int64   `json:"upstream_errors"`
	BytesFromUpstream int64   `json:"bytes_from_upstream"`
	BytesToClients    int64   `json:"bytes_to_clients"`
	Packages          int64   `json:"packages"`
}

// cacheStatsOut — DTO статистики кеша для /api/v1/cache/stats.
type cacheStatsOut struct {
	Hits              int64         `json:"hits"`
	Misses            int64         `json:"misses"`
	HitRatio          float64       `json:"hit_ratio"`
	StaleServed       int64         `json:"stale_served"`
	NegativeHits      int64         `json:"negative_hits"`
	UpstreamErrors    int64         `json:"upstream_errors"`
	BytesFromUpstream int64         `json:"bytes_from_upstream"`
	BytesToClients    int64         `json:"bytes_to_clients"`
	Packages          int64         `json:"packages"`
	PerEcosystem      []ecoStatsOut `json:"per_ecosystem"`
}

// handleCacheStats — GET /api/v1/cache/stats: агрегаты из metrics.Cache.
// Достаёт счётчики из движка кеша (Deps.Cache.Metrics), экспонирует в
// удобной для UI форме: hit_ratio отдельно, чтобы фронт не считал.
// Источник счётчиков — per-eco разрезы (сессия 83): глобальные
// значения — сумма per-eco на чтении, а не корневые поля (движок
// инкрементит только per-eco; единственный корневой писатель —
// BackgroundPanics).
func handleCacheStats(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Cache == nil {
			writeJSON(w, http.StatusOK, cacheStatsOut{PerEcosystem: []ecoStatsOut{}})
			return
		}
		m := d.Cache.Metrics()
		var hits, misses, stale, negative, upstreamErrors, bytesFromUpstream, bytesToClients, packages int64
		perEco := []ecoStatsOut{}
		m.EachEcosystem(func(name string, eco *metrics.Cache) {
			hits += eco.Hits.Load()
			misses += eco.Misses.Load()
			stale += eco.StaleServed.Load()
			negative += eco.NegativeHits.Load()
			upstreamErrors += eco.UpstreamErrors.Load()
			bytesFromUpstream += eco.BytesFromUpstream.Load()
			bytesToClients += eco.BytesToClients.Load()
			packages += eco.Packages.Load()
			var ratio float64
			if total := eco.Hits.Load() + eco.Misses.Load(); total > 0 {
				ratio = float64(eco.Hits.Load()) / float64(total)
			}
			perEco = append(perEco, ecoStatsOut{
				Ecosystem: name,
				Hits:      eco.Hits.Load(), Misses: eco.Misses.Load(), HitRatio: ratio,
				StaleServed:       eco.StaleServed.Load(),
				NegativeHits:      eco.NegativeHits.Load(),
				UpstreamErrors:    eco.UpstreamErrors.Load(),
				BytesFromUpstream: eco.BytesFromUpstream.Load(),
				BytesToClients:    eco.BytesToClients.Load(),
				Packages:          eco.Packages.Load(),
			})
		})
		var ratio float64
		if total := hits + misses; total > 0 {
			ratio = float64(hits) / float64(total)
		}
		writeJSON(w, http.StatusOK, cacheStatsOut{
			Hits: hits, Misses: misses, HitRatio: ratio,
			StaleServed:       stale,
			NegativeHits:      negative,
			UpstreamErrors:    upstreamErrors,
			BytesFromUpstream: bytesFromUpstream,
			BytesToClients:    bytesToClients,
			Packages:          packages,
			PerEcosystem:      perEco,
		})
	}
}

// handleCacheStatsReset — POST /api/v1/cache/stats/reset (сессия 97):
// обнуляет per-eco атомики, корневой BackgroundPanics и строки
// cache_stats. Ответ 204 пустой; идемпотентен. Сброс «половины»
// (только память) лгал бы: следующий рестарт вернул бы старые числа
// из БД — поэтому оба хранилища, в этом порядке.
func handleCacheStatsReset(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Action до мутации (урок сессии 87): неудачный сброс виден в
		// трейле под настоящим именем.
		*r = *r.WithContext(WithAuditAction(r.Context(), "cache.stats.reset"))
		if d.Cache == nil {
			// Нечего сбрасывать — идемпотентный 204.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		m := d.Cache.Metrics()
		// Сначала БД, потом атомики: флаш keeper'а (сессия 96) после
		// ResetStats прочитает уже обнулённые атомики и запишет нули;
		// флаш до ResetStats перезаписывается им. Обращённый порядок
		// оставил бы полусброс при сбое БД (атомики нули, строки — нет).
		if d.Stats != nil {
			if err := d.Stats.ResetStats(r.Context()); err != nil {
				writeErr(w, &domain.UnavailableError{What: "каталог", Reason: "сброс статистики", Err: err})
				return
			}
		}
		// Запись в переданный per-eco разрез легальна; вложенный
		// ForEcosystem запрещён (внешний замок) — и не зовётся.
		m.EachEcosystem(func(_ string, eco *metrics.Cache) {
			eco.Hits.Store(0)
			eco.Misses.Store(0)
			eco.StaleServed.Store(0)
			eco.NegativeHits.Store(0)
			eco.UpstreamErrors.Store(0)
			eco.BytesFromUpstream.Store(0)
			eco.BytesToClients.Store(0)
			eco.Packages.Store(0)
		})
		// BackgroundPanics — единственный корневой писатель (сессия 83):
		// без него сброс неполный.
		m.BackgroundPanics.Store(0)
		w.WriteHeader(http.StatusNoContent)
	}
}

// txnOut — DTO клиентской транзакции кеша для
// /api/v1/cache/transactions (сессия 100).
type txnOut struct {
	At        time.Time `json:"at"`
	Ecosystem string    `json:"ecosystem"`
	Path      string    `json:"path"`
	Status    string    `json:"status"`
	Size      int64     `json:"size"`
	Error     string    `json:"error"`
}

// txnOutFrom — модель cache.Txn → DTO.
func txnOutFrom(t cache.Txn) txnOut {
	return txnOut{
		At: t.At, Ecosystem: t.Ecosystem, Path: t.Path,
		Status: t.Status, Size: t.Size, Error: t.Err,
	}
}

// txnLimitMax — глубина кольцевого буфера движка (cache.txnCap): клиент,
// просящий больше буфера, получает 400, а не тихий clamp.
const txnLimitMax = 50

// handleCacheTransactions — GET /api/v1/cache/transactions?limit=:
// последние клиентские транзакции кеша newest-first. limit — «вернуть
// не более N последних», без пагинации: буфер — операционная память на
// 50, ключевая пагинация (как /audit) здесь избыточна. Чтение без
// аудита (прецедент /tasks и /cache/stats).
func handleCacheTransactions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := int64(txnLimitMax)
		if raw := r.URL.Query().Get("limit"); raw != "" {
			// Строгий ParseInt (урок сессии 88): мусорный хвост —
			// ошибка запроса, не префиксно-принятое число.
			v, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || v <= 0 || v > txnLimitMax {
				writeErr(w, &domain.ValidationError{What: "limit", Value: raw, Reason: "целое от 1 до 50"})
				return
			}
			limit = v
		}
		if d.Cache == nil {
			// Деградация без движка кеша — пустой список (образец
			// handleCacheStats).
			writeJSON(w, http.StatusOK, []txnOut{})
			return
		}
		txns := d.Cache.RecentTransactions(int(limit))
		out := make([]txnOut, 0, len(txns))
		for _, t := range txns {
			out = append(out, txnOutFrom(t))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// auditEntryOut — DTO записи аудита для /api/v1/audit.
type auditEntryOut struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Object string    `json:"object"`
	Result string    `json:"result"`
	Detail string    `json:"detail"`
}

// handleAuditPage — GET /api/v1/audit?after_id=&limit=: keyset-пагинация.
// after_id — последний ID, который видел клиент; limit — размер страницы.
func handleAuditPage(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Audit == nil {
			writeJSON(w, http.StatusOK, []auditEntryOut{})
			return
		}
		afterID := parseInt64Query(r, "after_id", 0)
		limit := parseInt64Query(r, "limit", 100)
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		entries, err := d.Audit.AuditEntries(r.Context(), afterID, int(limit))
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]auditEntryOut, 0, len(entries))
		for _, e := range entries {
			out = append(out, auditEntryOut{
				ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action,
				Object: e.Object, Result: e.Result, Detail: e.Detail,
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// usersOut — DTO пользователя без PasswordHash.
type usersOut struct {
	ID           int64       `json:"id"`
	Username     string      `json:"username"`
	Role         domain.Role `json:"role"`
	TokenVersion int64       `json:"token_version"`
	CreatedAt    time.Time   `json:"created_at"`
}

func userOut(u domain.User) usersOut {
	return usersOut{ID: u.ID, Username: u.Username, Role: u.Role, TokenVersion: u.TokenVersion, CreatedAt: u.CreatedAt}
}

// handleUsers переезд из handlers_auth: список пользователей.
func handleUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		us, err := d.Auth.Users(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]usersOut, 0, len(us))
		for _, u := range us {
			out = append(out, userOut(u))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleCreateUser переезд из handlers_auth: создание пользователя.
func handleCreateUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string      `json:"username"`
			Password string      `json:"password"`
			Role     domain.Role `json:"role"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Role == "" {
			in.Role = domain.RoleUser
		}
		// Action ставится ДО вызова движка (паттерн гранта, сессия 58):
		// движок пишет user.create сам, middleware-строка — под тем же
		// именем, иначе трейл показывал два имени одной операции
		// (user.create и fallback create.users).
		*r = *r.WithContext(WithAuditAction(r.Context(), "user.create"))
		u, err := d.Auth.CreateUser(r.Context(), in.Username, in.Password, in.Role)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, userOut(u))
	}
}

// handleDeleteUser переезд из handlers_auth.
func handleDeleteUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		// Action до движка — как в handleCreateUser: единое имя
		// user.delete для движковой и middleware-записи.
		*r = *r.WithContext(WithAuditAction(r.Context(), "user.delete"))
		if err := d.Auth.DeleteUser(r.Context(), id); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleCreateToken переезд из handlers_auth.
func handleCreateToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		u, err := d.Auth.User(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		var in struct {
			Name   string         `json:"name"`
			Scopes []domain.Scope `json:"scopes"`
			TTL    time.Duration  `json:"ttl"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		// ttl < 0 молча создавал бессрочный токен (engine смотрит только
		// ttl > 0) — REST-контракт ждёт валидацию: 0/отсутствие =
		// бессрочный, отрицательное — ошибка (аудит 2026-08-30).
		if in.TTL < 0 {
			writeErr(w, &domain.ValidationError{What: "ttl", Value: in.TTL.String(), Reason: "не может быть отрицательным"})
			return
		}
		t, raw, err := d.Auth.IssueAPIToken(r.Context(), u, in.Name, in.Scopes, in.TTL)
		if err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "user.api-token.create"))
		writeJSON(w, http.StatusCreated, map[string]any{
			"token": raw, "id": t.ID, "name": t.Name,
			"scopes": t.Scopes, "expires_at": t.ExpiresAt,
		})
	}
}

// tokenOut — DTO API-токена для списка: без SHA256 (хеш — внутренняя
// кухня), с префиксом для узнавания. Сырой токен отдаётся один раз —
// только в ответе создания (handleCreateToken). Нулевые времена —
// бессрочный/неотозванный токен (omitempty на time.Time не работает).
type tokenOut struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Prefix    string         `json:"prefix"`
	Scopes    []domain.Scope `json:"scopes"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	RevokedAt time.Time      `json:"revoked_at,omitempty"`
}

func tokenOutFrom(t domain.APIToken) tokenOut {
	scopes := t.Scopes
	if scopes == nil {
		scopes = []domain.Scope{}
	}
	return tokenOut{
		ID: t.ID, Name: t.Name, Prefix: t.Prefix, Scopes: scopes,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt,
	}
}

// handleListTokens переезд из handlers_auth.
func handleListTokens(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		ts, err := d.Auth.Tokens(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]tokenOut, 0, len(ts))
		for _, t := range ts {
			out = append(out, tokenOutFrom(t))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleRevokeToken переезд из handlers_auth. {id} из пути — владелец
// токена: revoke с чужим id срабатывал при любом пользователе в пути,
// нарушая контракт REST-адресации (аудит 2026-08-30). Несовпадение —
// 404 not_found (токена «у этого пользователя» нет).
func handleRevokeToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		tokenID, ok := parseInt64URLParam(w, r, "tokenID")
		if !ok {
			return
		}
		tokens, err := d.Auth.Tokens(r.Context(), userID)
		if err != nil {
			writeErr(w, err)
			return
		}
		owned := false
		for _, t := range tokens {
			if t.ID == tokenID {
				owned = true
				break
			}
		}
		if !owned {
			writeErrCode(w, http.StatusNotFound, "not_found")
			return
		}
		if err := d.Auth.RevokeToken(r.Context(), tokenID); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "user.api-token.revoke"))
		w.WriteHeader(http.StatusNoContent)
	}
}
