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

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/core/engine/eviction"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// Контракты eviction-API (сессия 202): политика в теле remote (tri-state
// PATCH), прогноз кандидатов, применение фоновой задачей (kind=eviction,
// label=remote-<id>), аудит до старта, деградации 503/400.

// evClockBase — «сейчас» харнесса (часы auth/tasks/движка). Версии
// кладутся заметно раньше: бутстрап-обращение (нет строки object_access →
// дата загрузки) иначе защитило бы все версии как «свежие».
var evClockBase = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const (
	evSeedStep = time.Hour             // шаг часов носителя: порядок записи = порядок свежести
	evSeedOld  = -200 * 24 * time.Hour // старт ModTime: вся пачка старше MaxAgeDays=90
)

// evVersions — сколько версий семейства кладут фикстуры (топ-N=3 → двое
// кандидатов).
const evVersions = 5

// evictionTestAdapter — двойник генератора с резолвером семейств
// кеш-путей (port.CacheFamilyResolver): семейство — каталог файла под
// pool/, всё вне pool/ — не семейство (индексы, подписи, служебные).
type evictionTestAdapter struct{ name string }

func (a *evictionTestAdapter) Name() string                    { return a.name }
func (a *evictionTestAdapter) ValidateObjectPath(string) error { return nil }

func (a *evictionTestAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}

func (a *evictionTestAdapter) CacheObjectFamily(path string) (string, bool) {
	p := strings.TrimPrefix(path, "/")
	if !strings.HasPrefix(p, "pool/") {
		return "", false
	}
	return p[:strings.LastIndexByte(p, '/')], true
}

// evictionNixAdapter — генератор БЕЗ CacheFamilyResolver (nix:
// content-addressed, старых версий одного пути не бывает).
type evictionNixAdapter struct{ name string }

func (a *evictionNixAdapter) Name() string                    { return a.name }
func (a *evictionNixAdapter) ValidateObjectPath(string) error { return nil }

func (a *evictionNixAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}

var (
	_ port.RepoAdapter         = (*evictionTestAdapter)(nil)
	_ port.CacheFamilyResolver = (*evictionTestAdapter)(nil)
	_ port.RepoAdapter         = (*evictionNixAdapter)(nil)
)

// evictionWebStub — склейка «движок eviction → web.EvictionAPI» для
// тестов: хендлеры знают только срез, а боевая склейка живёт в wire
// (evictionWebAPI), недоступном из пакета web. Образец — retentionWebStub.
type evictionWebStub struct {
	engine *eviction.Engine

	mu    sync.Mutex
	block chan struct{}
}

func (s *evictionWebStub) Preview(ctx context.Context, remote domain.Remote) (EvictionPreview, error) {
	res, reports, err := s.engine.Preview(ctx, remote)
	if err != nil {
		return EvictionPreview{}, err
	}
	out := EvictionPreview{Totals: evictionTotalsFrom(res), Candidates: make([]EvictionCandidate, 0, len(reports))}
	for _, r := range reports {
		out.Candidates = append(out.Candidates, EvictionCandidate{
			Key: r.Key, Family: r.Family, Size: r.Size,
			ModTime: r.ModTime, LastAccess: r.LastAccess, ProtectedBy: r.ProtectedBy,
		})
	}
	return out, nil
}

func (s *evictionWebStub) Apply(ctx context.Context, remote domain.Remote) (EvictionTotals, error) {
	// Заблокированный проход держит задачу активной: так тест 409
	// гарантирует, что задача-победитель ещё идёт, а не «успела».
	s.mu.Lock()
	block := s.block
	s.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return EvictionTotals{}, ctx.Err()
		}
	}
	res, err := s.engine.Apply(ctx, remote, false)
	return evictionTotalsFrom(res), err
}

// setBlock — заставляет боевой проход ждать закрытия канала.
func (s *evictionWebStub) setBlock(ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = ch
}

// evictionTotalsFrom — тестовый двойник конвертера счётчиков из wire.
func evictionTotalsFrom(res eviction.Result) EvictionTotals {
	return EvictionTotals{
		DryRun: res.DryRun, DurationSeconds: res.Duration.Seconds(),
		Families: res.Families, ObjectsScanned: res.ObjectsScanned,
		Candidates: res.Candidates, Deleted: res.Deleted,
		FailedDeletes: res.FailedDeletes, BytesFreed: res.BytesFreed,
		ProtectedByMin: res.ProtectedByMin, ProtectedByAccess: res.ProtectedByAccess,
	}
}

// evictionEnv — живой движок eviction на фейках + админ-роутер (образец
// retentionEnv): контрактам /remotes/{id}/eviction/* нужен настоящий
// проход, а не заглушка. Часы носителя отдельные: сдвиг ModTime версий в
// прошлое не должен просрочивать admin-JWT (SessionTTL=1h).
type evictionEnv struct {
	handler   http.Handler
	auth      *auth.Service
	remotes   *testutil.FakeRemoteStore
	storage   *testutil.FakeStorage
	access    *testutil.FakeAccessStore
	audit     *testutil.FakeAuditLog
	tasks     *TaskRegistry
	clock     *testutil.ManualClock
	seedClock *testutil.ManualClock
	stub      *evictionWebStub
	jwtAdmin  string
	jwtUser   string
	remoteID  int64
	nixID     int64
}

func newEvictionEnv(t *testing.T) *evictionEnv {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tokens := &handlerTokens{}
	clock := testutil.NewManualClock(evClockBase)
	a, err := auth.New(auth.Config{
		Users: users, Tokens: tokens, Audit: nil, Revocations: testutil.NewFakeRevocations(),
		Clock: clock, Rand: testutil.FixedRand(
			"77777777-7777-4777-8777-777777777771",
			"77777777-7777-4777-8777-777777777772",
			"77777777-7777-4777-8777-777777777773",
			"77777777-7777-4777-8777-777777777774",
		),
		JWTSecret: "secret", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.CreateUser(t.Context(), "admin", "password", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := a.CreateUser(t.Context(), "user", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	jwtAdmin, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	jwtUser, err := a.IssueSession(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	remotes := testutil.NewFakeRemoteStore()
	seedClock := testutil.NewManualClock(evClockBase.Add(evSeedOld))
	storage := testutil.NewFakeStorage(seedClock)
	access := testutil.NewFakeAccessStore()
	adapters := map[string]port.RepoAdapter{
		"apt": &evictionTestAdapter{name: "apt"},
		"nix": &evictionNixAdapter{name: "nix"},
	}
	engine := eviction.New(storage, access, adapters, clock, domain.Retention{})
	stub := &evictionWebStub{engine: engine}
	auditLog := testutil.NewFakeAuditLog()
	tasks := NewTaskRegistry(2, clock, nil)
	handler := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Remotes: remotes, Audit: auditLog, Tasks: tasks, Clock: clock,
		Eviction: stub,
	})
	deb, err := remotes.CreateRemote(t.Context(), domain.Remote{
		ID: 0, Name: "deb-main", Ecosystem: "apt", BaseURL: "https://deb.example.org",
		Mode: domain.ModeProxy, Enabled: true, CreatedAt: clock.Now(),
		Eviction: &domain.Retention{MinVersions: 3, MaxAgeDays: 90},
	})
	if err != nil {
		t.Fatal(err)
	}
	nix, err := remotes.CreateRemote(t.Context(), domain.Remote{
		Name: "nix-cache", Ecosystem: "nix", BaseURL: "https://cache.nixos.org",
		Mode: domain.ModeProxy, Enabled: true, CreatedAt: clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &evictionEnv{
		handler: handler, auth: a, remotes: remotes, storage: storage, access: access,
		audit: auditLog, tasks: tasks, clock: clock, seedClock: seedClock, stub: stub,
		jwtAdmin: jwtAdmin, jwtUser: jwtUser, remoteID: deb.ID, nixID: nix.ID,
	}
}

// call — HTTP-вызов админ-роутера с опциональным bearer.
func (e *evictionEnv) call(t *testing.T, method, path, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "10.0.0.9:1"
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, r)
	return rec
}

// evPath — путь eviction-маршрута remote.
func (e *evictionEnv) evPath(remoteID int64, tail string) string {
	return "/api/v1/remotes/" + strconv.FormatInt(remoteID, 10) + "/eviction" + tail
}

// versionKey — ключ i-й версии семейства htop в кеше remote.
func (e *evictionEnv) versionKey(i int) string {
	return "cache/apt/" + strconv.FormatInt(e.remoteID, 10) +
		fmt.Sprintf("/pool/main/h/htop/htop_%d_amd64.deb", i)
}

// seedVersions кладёт n версий одного семейства; ModTime идут по
// возрастанию (шаг evSeedStep), то есть свежесть = номер версии.
func (e *evictionEnv) seedVersions(t *testing.T, n int) []string {
	t.Helper()
	keys := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		key := e.versionKey(i)
		gcPut(t, e.storage, key)
		keys = append(keys, key)
		e.seedClock.Advance(evSeedStep)
	}
	return keys
}

// setPolicy — политика remote напрямую в каталоге (API-путь PATCH
// проверяется отдельным тестом).
func (e *evictionEnv) setPolicy(t *testing.T, remoteID int64, ret *domain.Retention) {
	t.Helper()
	rem, err := e.remotes.Remote(t.Context(), remoteID)
	if err != nil {
		t.Fatal(err)
	}
	rem.Eviction = ret
	if err := e.remotes.UpdateRemote(t.Context(), rem); err != nil {
		t.Fatal(err)
	}
}

// remotePolicy — текущая политика remote из каталога.
func (e *evictionEnv) remotePolicy(t *testing.T, remoteID int64) *domain.Retention {
	t.Helper()
	rem, err := e.remotes.Remote(t.Context(), remoteID)
	if err != nil {
		t.Fatal(err)
	}
	return rem.Eviction
}

// preview — GET прогноза; тело разбирается только на 200.
func (e *evictionEnv) preview(t *testing.T, remoteID int64, bearer string) (EvictionPreview, int) {
	t.Helper()
	rec := e.call(t, http.MethodGet, e.evPath(remoteID, "/preview"), "", bearer)
	var out EvictionPreview
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("разбор прогноза: %v (тело %s)", err, rec.Body.String())
		}
	}
	return out, rec.Code
}

// apply — POST запуска приложения; возвращает пару (task_id, код).
func (e *evictionEnv) apply(t *testing.T, remoteID int64, bearer string) (string, int) {
	t.Helper()
	rec := e.call(t, http.MethodPost, e.evPath(remoteID, "/apply"), "", bearer)
	if rec.Code != http.StatusAccepted {
		return "", rec.Code
	}
	var resp struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор task_id: %v", err)
	}
	if resp.TaskID == "" {
		t.Fatal("task_id пуст")
	}
	return resp.TaskID, rec.Code
}

// TestEvictionPreviewCandidates — прогноз: 5 версий семейства при
// политике {3,90} → 200, два кандидата (две самые старые версии), защита
// топ-N посчитана, носитель не тронут; не-админ — 403 (admin-маршрут).
func TestEvictionPreviewCandidates(t *testing.T) {
	t.Parallel()
	e := newEvictionEnv(t)
	keys := e.seedVersions(t, evVersions)

	out, code := e.preview(t, e.remoteID, e.jwtAdmin)
	if code != http.StatusOK {
		t.Fatalf("GET preview = %d, хочу 200", code)
	}
	if !out.Totals.DryRun {
		t.Error("прогноз не помечен dry_run")
	}
	if len(out.Candidates) != 2 || out.Totals.Candidates != 2 {
		t.Fatalf("кандидатов %d (totals %d), хочу 2", len(out.Candidates), out.Totals.Candidates)
	}
	if out.Totals.ProtectedByMin != 3 {
		t.Errorf("защита топ-N = %d, хочу 3", out.Totals.ProtectedByMin)
	}
	if out.Totals.Deleted != 0 {
		t.Errorf("dry-run удалил %d объектов", out.Totals.Deleted)
	}
	for _, c := range out.Candidates {
		if c.ProtectedBy != "" {
			t.Errorf("кандидат %s защищён «%s»", c.Key, c.ProtectedBy)
		}
		if c.Family != "pool/main/h/htop" {
			t.Errorf("семейство кандидата %s = %q", c.Key, c.Family)
		}
		if c.Size == 0 || c.ModTime.IsZero() || c.LastAccess.IsZero() {
			t.Errorf("строка кандидата %s неполна: %+v", c.Key, c)
		}
	}
	// Жертвы — две самые старые версии семейства.
	for _, c := range out.Candidates {
		if c.Key != keys[0] && c.Key != keys[1] {
			t.Errorf("кандидат %s не из двух старейших версий", c.Key)
		}
	}
	for _, k := range keys {
		if !gcHas(t, e.storage, k) {
			t.Errorf("dry-run удалил объект %s", k)
		}
	}
	// Чтение прогноза — мутаций нет, аудит не пишется (как у ретеншна).
	if entries, err := e.audit.AuditEntries(t.Context(), 0, 100); err != nil || len(entries) != 0 {
		t.Errorf("прогноз оставил аудит-записи: %+v (%v)", entries, err)
	}
	if _, code := e.preview(t, e.remoteID, e.jwtUser); code != http.StatusForbidden {
		t.Errorf("preview не-админом = %d, хочу 403", code)
	}
}

// TestEvictionApplyDeletes — apply: 202+task_id, задача доходит до
// succeeded, кандидаты удалены, защищённые версии целы; аудит —
// remote.eviction.apply/ok.
func TestEvictionApplyDeletes(t *testing.T) {
	t.Parallel()
	e := newEvictionEnv(t)
	keys := e.seedVersions(t, evVersions)

	taskID, code := e.apply(t, e.remoteID, e.jwtAdmin)
	if code != http.StatusAccepted {
		t.Fatalf("POST apply = %d, хочу 202", code)
	}
	snap := awaitState(t, e.tasks, taskID, taskSucceeded)
	if !strings.Contains(strings.Join(snap.Logs, "\n"), "проход завершён") {
		t.Errorf("лог задачи без итога прохода: %+v", snap.Logs)
	}
	for _, k := range keys[:2] {
		if gcHas(t, e.storage, k) {
			t.Errorf("кандидат %s жив после apply", k)
		}
	}
	for _, k := range keys[2:] {
		if !gcHas(t, e.storage, k) {
			t.Errorf("защищённая версия %s удалена", k)
		}
	}
	if entry := lastAudit(t, e.audit); entry.Action != "remote.eviction.apply" || entry.Result != domain.AuditOK {
		t.Errorf("аудит: %+v, хочу remote.eviction.apply/ok", entry)
	}
}

// TestEvictionApplyConflictWhileRunning — повторный apply того же remote
// при активной задаче → 409, и запись аудита идёт под настоящим именем
// действия (урок сессии 87: action ставится ДО запуска задачи); задача-
// победитель доигрывается до succeeded.
func TestEvictionApplyConflictWhileRunning(t *testing.T) {
	t.Parallel()
	e := newEvictionEnv(t)
	e.seedVersions(t, evVersions)

	block := make(chan struct{})
	e.stub.setBlock(block)
	taskID, code := e.apply(t, e.remoteID, e.jwtAdmin)
	if code != http.StatusAccepted {
		t.Fatalf("первый POST apply = %d, хочу 202", code)
	}
	_, code = e.apply(t, e.remoteID, e.jwtAdmin)
	if code != http.StatusConflict {
		t.Fatalf("повторный POST apply = %d, хочу 409", code)
	}
	if entry := lastAudit(t, e.audit); entry.Action != "remote.eviction.apply" || entry.Result != "409" {
		t.Errorf("аудит конфликта: %+v, хочу remote.eviction.apply/409", entry)
	}
	close(block)
	awaitState(t, e.tasks, taskID, taskSucceeded)
}

// TestEvictionDegradation — nil-движок (деградация) → 503
// eviction_unavailable на обоих маршрутах; nix-remote (адаптер без
// резолвера семейств) → 400 eviction_unsupported на прогнозе.
func TestEvictionDegradation(t *testing.T) {
	t.Parallel()
	e := newEvictionEnv(t)

	// nix: Content-addressed, семейств нет — политика неприменима.
	// Политику задаём явно: у выключенной проход вообще не доходит до
	// резолвера (движок выходит на policy.Enabled()) и вопрос экосистемы
	// не встаёт.
	e.setPolicy(t, e.nixID, &domain.Retention{MinVersions: 3, MaxAgeDays: 90})
	rec := e.call(t, http.MethodGet, e.evPath(e.nixID, "/preview"), "", e.jwtAdmin)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "eviction_unsupported") {
		t.Errorf("preview nix-remote = %d %s, хочу 400 eviction_unsupported", rec.Code, rec.Body.String())
	}

	// Деградация: у роутера нет движка — оба маршрута отдают 503 с
	// одним кодом (образец retention_unavailable).
	deg := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: e.auth, Remotes: e.remotes,
		Audit: e.audit, Tasks: e.tasks, Clock: e.clock,
	})
	call := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "10.0.0.9:1"
		r.Header.Set("Authorization", "Bearer "+e.jwtAdmin)
		w := httptest.NewRecorder()
		deg.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, e.evPath(e.remoteID, "/preview")},
		{http.MethodPost, e.evPath(e.remoteID, "/apply")},
	} {
		rec := call(tc.method, tc.path)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "eviction_unavailable") {
			t.Errorf("%s %s = %d %s, хочу 503 eviction_unavailable", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

// TestRemoteEvictionPolicyViaAPI — политика eviction в теле remote:
// tri-state PATCH (ключа нет → политика не тронута, null → сброс в
// наследование, объект → полная замена; {1,90} — 400 доменной
// валидации) и объект при создании remote.
func TestRemoteEvictionPolicyViaAPI(t *testing.T) {
	t.Parallel()
	e := newEvictionEnv(t)
	path := "/api/v1/remotes/" + strconv.FormatInt(e.remoteID, 10)
	// Тело PATCH — full-replace прочих полей (контракт PATCH /remotes),
	// eviction подставляется вызывающим.
	patch := func(eviction string) *httptest.ResponseRecorder {
		body := `{"name":"deb-main","ecosystem":"apt","base_url":"https://deb.example.org","mode":"proxy","sync_interval":0,"include":[]` + eviction + `}`
		return e.call(t, http.MethodPatch, path, body, e.jwtAdmin)
	}

	// Ключа нет — настроенная политика {3,90} сохраняется (не сброс).
	rec := patch("")
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH без eviction = %d, хочу 200 (тело %s)", rec.Code, rec.Body.String())
	}
	if got := e.remotePolicy(t, e.remoteID); got == nil || got.MinVersions != 3 || got.MaxAgeDays != 90 {
		t.Fatalf("политика после PATCH без поля = %+v, хочу {3 90}", got)
	}
	var out remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Eviction == nil || out.Eviction.MinVersions != 3 || out.Eviction.MaxAgeDays != 90 {
		t.Errorf("ответ PATCH несёт eviction %+v, хочу {3 90}", out.Eviction)
	}

	// null — сброс в наследование глобального дефолта.
	rec = patch(`,"eviction":null`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH eviction=null = %d, хочу 200 (тело %s)", rec.Code, rec.Body.String())
	}
	if got := e.remotePolicy(t, e.remoteID); got != nil {
		t.Errorf("после eviction=null политика = %+v, хочу nil (наследование)", got)
	}

	// Объект — полная замена.
	rec = patch(`,"eviction":{"min_versions":2,"max_age_days":90}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH eviction={2,90} = %d, хочу 200 (тело %s)", rec.Code, rec.Body.String())
	}
	if got := e.remotePolicy(t, e.remoteID); got == nil || got.MinVersions != 2 || got.MaxAgeDays != 90 {
		t.Errorf("политика после {2,90} = %+v, хотим {2 90}", got)
	}

	// {1,90} — окно 404 (доменное правило) → 400 validation_error.
	rec = patch(`,"eviction":{"min_versions":1,"max_age_days":90}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "validation_error") {
		t.Errorf("PATCH eviction={1,90} = %d %s, хочу 400 validation_error", rec.Code, rec.Body.String())
	}
	if got := e.remotePolicy(t, e.remoteID); got == nil || got.MinVersions != 2 {
		t.Errorf("отклонённый PATCH изменил политику: %+v", got)
	}

	// GET списка отдаёт политику тем же DTO (null — наследование).
	rec = e.call(t, http.MethodGet, "/api/v1/remotes", "", e.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /remotes = %d, хочу 200", rec.Code)
	}
	var list []remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, rem := range list {
		if rem.Name == "nix-cache" && rem.Eviction != nil {
			t.Errorf("remote без политики отдан с eviction %+v, хочу null", rem.Eviction)
		}
	}

	// Создание remote с политикой: объект полем — 201, политика в ответе.
	rec = e.call(t, http.MethodPost, "/api/v1/remotes",
		`{"name":"deb-new","ecosystem":"apt","base_url":"https://deb2.example.org","mode":"proxy","eviction":{"min_versions":4,"max_age_days":30}}`,
		e.jwtAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /remotes с eviction = %d, хочу 201 (тело %s)", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Eviction == nil || out.Eviction.MinVersions != 4 || out.Eviction.MaxAgeDays != 30 {
		t.Errorf("ответ POST несёт eviction %+v, хочу {4 30}", out.Eviction)
	}
}
