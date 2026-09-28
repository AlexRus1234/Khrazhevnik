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
	"khrazhevnik/internal/core/engine/retention"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// clockBase — «сейчас» харнесса (часы auth/tasks/движка). Версии кладутся
// заметно раньше (seedOld): бутстрап-обращение (нет строки object_access →
// дата загрузки) иначе защитило бы все версии как «свежие», и кандидатов
// в фикстурах не осталось бы вовсе.
var clockBase = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

const (
	seedStep = time.Hour             // шаг часов носителя: порядок записи = порядок свежести
	seedOld  = -200 * 24 * time.Hour // старт ModTime: вся пачка старше MaxAgeDays=90
)

// retVersions — сколько версий семейства кладут фикстуры большинства
// тестов (топ-N=3 → двое кандидатов).
const retVersions = 5

// retentionTestAdapter — двойник адаптера экосистемы: семейство —
// каталог файла под pool/ (механика apt, сессия 169), всё вне pool/ — не
// семейство (индексы, подписи). GenerateIndexes считает вызовы и умеет
// блокироваться: так тест гарантирует, что задача действительно активна
// (409 при повторном apply).
type retentionTestAdapter struct {
	name string

	mu    sync.Mutex
	calls int
	block chan struct{}
}

func (a *retentionTestAdapter) Name() string                    { return a.name }
func (a *retentionTestAdapter) ValidateObjectPath(string) error { return nil }

func (a *retentionTestAdapter) ObjectFamily(p string) (string, bool) {
	if !strings.HasPrefix(p, "pool/") {
		return "", false
	}
	return p[:strings.LastIndexByte(p, '/')], true
}

func (a *retentionTestAdapter) GenerateIndexes(ctx context.Context, _ domain.Repo, _ port.Storage, _ port.RepoProgress) error {
	a.mu.Lock()
	a.calls++
	block := a.block
	a.mu.Unlock()
	if block == nil {
		return nil
	}
	select {
	case <-block:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// reindexCalls — сколько раз движок позвал генерацию индексов.
func (a *retentionTestAdapter) reindexCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// setBlock — заставляет генерацию индексов ждать закрытия канала.
func (a *retentionTestAdapter) setBlock(ch chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.block = ch
}

// retentionWebStub — склейка «движок ретеншна → web.RetentionAPI» для
// тестов: хендлеры знают только срез, а боевая склейка живёт в wire
// (retentionWebAPI), недоступном из пакета web. Образец — mirrorStub.
type retentionWebStub struct {
	engine *retention.Engine
	pins   port.PinStore
}

func (s retentionWebStub) Preview(ctx context.Context, repo domain.Repo) (RetentionPreview, error) {
	res, reports, err := s.engine.Preview(ctx, repo)
	if err != nil {
		return RetentionPreview{}, err
	}
	out := RetentionPreview{Totals: retentionTotalsFrom(res), Candidates: make([]RetentionCandidate, 0, len(reports))}
	for _, r := range reports {
		out.Candidates = append(out.Candidates, RetentionCandidate{
			Key: r.Key, Family: r.Family, Size: r.Size,
			ModTime: r.ModTime, LastAccess: r.LastAccess, ProtectedBy: r.ProtectedBy,
		})
	}
	return out, nil
}

func (s retentionWebStub) ApplyAndReindex(ctx context.Context, repo domain.Repo, dryRun bool) (RetentionTotals, error) {
	res, err := s.engine.ApplyAndReindex(ctx, repo, dryRun)
	return retentionTotalsFrom(res), err
}

func (s retentionWebStub) Pins(ctx context.Context, repoID int64) ([]string, error) {
	return s.pins.Pins(ctx, repoID)
}

func (s retentionWebStub) SetPin(ctx context.Context, repoID int64, key string, pinned bool) error {
	return s.pins.SetPin(ctx, repoID, key, pinned)
}

// retentionTotalsFrom — тестовый двойник конвертера счётчиков из wire.
func retentionTotalsFrom(res retention.Result) RetentionTotals {
	return RetentionTotals{
		DryRun: res.DryRun, DurationSeconds: res.Duration.Seconds(),
		Families: res.Families, ObjectsScanned: res.ObjectsScanned,
		Candidates: res.Candidates, Deleted: res.Deleted,
		FailedDeletes: res.FailedDeletes, BytesFreed: res.BytesFreed,
		ProtectedByMin: res.ProtectedByMin, ProtectedByAccess: res.ProtectedByAccess,
		ProtectedByPin: res.ProtectedByPin,
	}
}

// retentionEnv — живой движок ретеншна на фейках + админ-роутер (образец
// gcHarness сессии 121): контрактам /repos/{id}/retention/* нужен
// настоящий проход, а не заглушка. Часы носителя отдельные: сдвиг ModTime
// версий в прошлое не должен просрочивать admin-JWT (SessionTTL=1h).
type retentionEnv struct {
	handler   http.Handler
	auth      *auth.Service
	repos     *testutil.FakeRepoStore
	storage   *testutil.FakeStorage
	access    *testutil.FakeAccessStore
	pins      *testutil.FakePinStore
	adapter   *retentionTestAdapter
	audit     *testutil.FakeAuditLog
	tasks     *TaskRegistry
	clock     *testutil.ManualClock
	seedClock *testutil.ManualClock
	jwtAdmin  string
	jwtUser   string
	jwtOther  string
	ownerID   int64
	repoID    int64
	otherID   int64
}

func newRetentionEnv(t *testing.T) *retentionEnv {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tokens := &handlerTokens{}
	clock := testutil.NewManualClock(clockBase)
	a, err := auth.New(auth.Config{
		Users: users, Tokens: tokens, Audit: nil, Revocations: testutil.NewFakeRevocations(),
		Clock: clock,
		// Разные UUID: одинаковый seed дал бы одинаковые сырые токены, а
		// значит и одинаковый SHA256 — «чужой» scoped-токен резолвился бы
		// в свой (TokenBySHA256 нашёл бы первый из совпавших).
		Rand: testutil.FixedRand(
			"88888888-8888-4888-8888-888888888881",
			"88888888-8888-4888-8888-888888888882",
			"88888888-8888-4888-8888-888888888883",
			"88888888-8888-4888-8888-888888888884",
			"88888888-8888-4888-8888-888888888885",
			"88888888-8888-4888-8888-888888888886",
			"88888888-8888-4888-8888-888888888887",
			"88888888-8888-4888-8888-888888888888",
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
	alice, err := a.CreateUser(t.Context(), "alice", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := a.CreateUser(t.Context(), "bob", "password", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	jwtAdmin, err := a.IssueSession(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	jwtUser, err := a.IssueSession(t.Context(), alice)
	if err != nil {
		t.Fatal(err)
	}
	jwtOther, err := a.IssueSession(t.Context(), bob)
	if err != nil {
		t.Fatal(err)
	}
	repos := testutil.NewFakeRepoStore()
	seedClock := testutil.NewManualClock(clockBase.Add(seedOld))
	storage := testutil.NewFakeStorage(seedClock)
	access := testutil.NewFakeAccessStore()
	pins := testutil.NewFakePinStore()
	adapter := &retentionTestAdapter{name: "apt"}
	engine := retention.New(storage, repos, access, map[string]port.RepoAdapter{"apt": adapter}, pins, clock)
	auditLog := testutil.NewFakeAuditLog()
	tasks := NewTaskRegistry(2, clock, nil)
	handler := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Ecosystems: map[string]port.Ecosystem{"apt": testutil.FakeEcosystem{NameOf: "apt"}},
		Repos:      repos, Storage: storage, Audit: auditLog, Tasks: tasks, Clock: clock,
		Retention: retentionWebStub{engine: engine, pins: pins},
	})
	live, err := repos.CreateRepo(t.Context(), domain.Repo{
		Name: "live", OwnerID: alice.ID, Ecosystem: "apt", CreatedAt: clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := repos.CreateRepo(t.Context(), domain.Repo{
		Name: "other", OwnerID: alice.ID, Ecosystem: "apt", CreatedAt: clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &retentionEnv{
		handler: handler, auth: a, repos: repos, storage: storage, access: access,
		pins: pins, adapter: adapter, audit: auditLog, tasks: tasks,
		clock: clock, seedClock: seedClock,
		jwtAdmin: jwtAdmin, jwtUser: jwtUser, jwtOther: jwtOther,
		ownerID: alice.ID,
		repoID:  live.ID,
		otherID: other.ID,
	}
}

// call — HTTP-вызов админ-роутера с опциональным bearer.
func (e *retentionEnv) call(t *testing.T, method, path, body, bearer string) *httptest.ResponseRecorder {
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

// versionKey — ключ i-й версии семейства htop в хранилище репо.
func (e *retentionEnv) versionKey(repoID int64, i int) string {
	return port.RepoPrefix(domain.Repo{ID: repoID, Ecosystem: "apt"}) +
		fmt.Sprintf("/pool/main/h/htop/htop_%d_amd64.deb", i)
}

// seedVersions кладёт n версий одного семейства; ModTime идут по
// возрастанию (шаг seedStep), то есть свежесть = номер версии.
func (e *retentionEnv) seedVersions(t *testing.T, n int) []string {
	t.Helper()
	keys := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		key := e.versionKey(e.repoID, i)
		gcPut(t, e.storage, key)
		keys = append(keys, key)
		e.seedClock.Advance(seedStep)
	}
	return keys
}

// setPolicy — политика репо напрямую в каталоге (API-путь PATCH
// проверяется отдельным тестом).
func (e *retentionEnv) setPolicy(t *testing.T, repoID int64, ret domain.Retention) {
	t.Helper()
	repo, err := e.repos.Repo(t.Context(), repoID)
	if err != nil {
		t.Fatal(err)
	}
	repo.Retention = ret
	if err := e.repos.UpdateRepo(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
}

// repoPolicy — текущая политика репо из каталога.
func (e *retentionEnv) repoPolicy(t *testing.T, repoID int64) domain.Retention {
	t.Helper()
	repo, err := e.repos.Repo(t.Context(), repoID)
	if err != nil {
		t.Fatal(err)
	}
	return repo.Retention
}

// preview — GET прогноза; тело разбирается только на 200.
func (e *retentionEnv) preview(t *testing.T, repoID int64, bearer string) (RetentionPreview, int) {
	t.Helper()
	rec := e.call(t, http.MethodGet, e.path(repoID, "/retention/preview"), "", bearer)
	var out RetentionPreview
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("разбор прогноза: %v (тело %s)", err, rec.Body.String())
		}
	}
	return out, rec.Code
}

// apply — POST запуска приложения; возвращает пару (task_id, код).
func (e *retentionEnv) apply(t *testing.T, repoID int64, bearer string) (string, int) {
	t.Helper()
	rec := e.call(t, http.MethodPost, e.path(repoID, "/retention/apply"), "", bearer)
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

// path — путь маршрута репо.
func (e *retentionEnv) path(repoID int64, tail string) string {
	return "/api/v1/repos/" + strconv.FormatInt(repoID, 10) + tail
}

// pin — PUT/DELETE пина по пути внутри репо.
func (e *retentionEnv) pin(t *testing.T, method, key, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	return e.call(t, method, e.path(e.repoID, "/retention/pins/"+key), "", bearer)
}

// versionTail — путь версии внутри репо (то, что шлёт GUI: ключ таблицы
// объектов без префикса репо).
func versionTail(i int) string {
	return fmt.Sprintf("pool/main/h/htop/htop_%d_amd64.deb", i)
}

// writeToken — scoped-токен repo:<repoID>:write для пользователя userID.
func (e *retentionEnv) writeToken(t *testing.T, userID, repoID int64) string {
	t.Helper()
	u, err := e.auth.User(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []domain.Scope{domain.Scope("repo:" + strconv.FormatInt(repoID, 10) + ":write")}
	_, raw, err := e.auth.IssueAPIToken(t.Context(), u, "repo-write", scopes, 0)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// waitReindex — ждёт, пока задача apply дойдёт до генерации индексов:
// только тогда она гарантированно активна, и повторный POST обязан
// увидеть 409 (без гонки «успел/не успел»).
func waitReindex(t *testing.T, a *retentionTestAdapter, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a.reindexCalls() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("адаптер не дошёл до генерации индексов: %d вызов(ов), жду %d", a.reindexCalls(), want)
}

// TestRepoRetentionPolicyViaAPI — политика — поле репо (PATCH full-replace,
// сессия 172): {3,90} читается обратно, {1,90} отвергается доменной
// валидацией (окно 404: последняя версия удалялась бы по возрасту),
// {0,0} — легальный сброс политики.
func TestRepoRetentionPolicyViaAPI(t *testing.T) {
	e := newRetentionEnv(t)
	path := e.path(e.repoID, "")
	patch := func(ret string) *httptest.ResponseRecorder {
		body := `{"name":"live","owner_id":` + strconv.FormatInt(e.ownerID, 10) +
			`,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0},"retention":` + ret + `}`
		return e.call(t, http.MethodPatch, path, body, e.jwtAdmin)
	}

	rec := patch(`{"min_versions":3,"max_age_days":90}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH retention {3,90} = %d, хочу 200 (тело %s)", rec.Code, rec.Body.String())
	}
	var out repoOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Retention.MinVersions != 3 || out.Retention.MaxAgeDays != 90 {
		t.Fatalf("ответ PATCH несёт retention %+v, хочу {3 90}", out.Retention)
	}
	got := e.repoPolicy(t, e.repoID)
	if got.MinVersions != 3 || got.MaxAgeDays != 90 {
		t.Fatalf("политика в каталоге = %+v, хочу {3 90}", got)
	}
	// GET отдаёт политику тем же DTO.
	rec = e.call(t, http.MethodGet, path, "", e.jwtAdmin)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Retention.MinVersions != 3 || out.Retention.MaxAgeDays != 90 {
		t.Errorf("GET /repos/{id} несёт retention %+v, хочу {3 90}", out.Retention)
	}

	// MinVersions=1 при заданном возрасте — окно 404 (доменное правило).
	rec = patch(`{"min_versions":1,"max_age_days":90}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "validation_error") {
		t.Errorf("PATCH {1,90} = %d %s, хочу 400 validation_error", rec.Code, rec.Body.String())
	}

	rec = patch(`{"min_versions":0,"max_age_days":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH {0,0} = %d, хочу 200 (тело %s)", rec.Code, rec.Body.String())
	}
	if got := e.repoPolicy(t, e.repoID); got.Enabled() {
		t.Errorf("после {0,0} политика = %+v, хочу выключенную", got)
	}
}

// TestRetentionPreviewCandidates — прогноз: репо 5 версий/MinVersions=3 →
// 200, два кандидата (две самые старые версии), защита топ-N посчитана;
// dry-run ничего не удалил и индексы не трогал.
func TestRetentionPreviewCandidates(t *testing.T) {
	e := newRetentionEnv(t)
	keys := e.seedVersions(t, retVersions)
	e.setPolicy(t, e.repoID, domain.Retention{MinVersions: 3, MaxAgeDays: 90})

	out, code := e.preview(t, e.repoID, e.jwtAdmin)
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
	if n := e.adapter.reindexCalls(); n != 0 {
		t.Errorf("прогноз перегенерировал индексы %d раз, хочу 0", n)
	}
}

// TestRetentionApplyDeletesAndReindexes — apply: 202+task_id, задача
// доходит до succeeded, жертвы удалены, живые версии целы, индексы
// перегенерированы тем же адаптером; аудит — repo.retention.apply/ok.
func TestRetentionApplyDeletesAndReindexes(t *testing.T) {
	e := newRetentionEnv(t)
	keys := e.seedVersions(t, retVersions)
	e.setPolicy(t, e.repoID, domain.Retention{MinVersions: 3, MaxAgeDays: 90})

	taskID, code := e.apply(t, e.repoID, e.jwtAdmin)
	if code != http.StatusAccepted {
		t.Fatalf("POST apply = %d, хочу 202", code)
	}
	snap := awaitState(t, e.tasks, taskID, taskSucceeded)
	if !strings.Contains(strings.Join(snap.Logs, "\n"), "проход завершён") {
		t.Errorf("лог задачи без итога прохода: %+v", snap.Logs)
	}
	for _, k := range keys[:2] {
		if gcHas(t, e.storage, k) {
			t.Errorf("жертва %s жива после apply", k)
		}
	}
	for _, k := range keys[2:] {
		if !gcHas(t, e.storage, k) {
			t.Errorf("защищённая версия %s удалена", k)
		}
	}
	if n := e.adapter.reindexCalls(); n != 1 {
		t.Errorf("генераций индексов %d, хочу 1", n)
	}
	if entry := lastAudit(t, e.audit); entry.Action != "repo.retention.apply" || entry.Result != domain.AuditOK {
		t.Errorf("аудит: %+v, хочу repo.retention.apply/ok", entry)
	}
}

// TestRetentionApplyConflictWhileRunning — повторный apply того же репо при
// активной задаче → 409 (ErrTaskDuplicate → statusFor), задача-победитель
// доигрывается до succeeded.
func TestRetentionApplyConflictWhileRunning(t *testing.T) {
	e := newRetentionEnv(t)
	e.seedVersions(t, retVersions)
	e.setPolicy(t, e.repoID, domain.Retention{MinVersions: 3, MaxAgeDays: 90})

	block := make(chan struct{})
	e.adapter.setBlock(block)
	taskID, code := e.apply(t, e.repoID, e.jwtAdmin)
	if code != http.StatusAccepted {
		t.Fatalf("первый POST apply = %d, хочу 202", code)
	}
	waitReindex(t, e.adapter, 1)

	rec := e.call(t, http.MethodPost, e.path(e.repoID, "/retention/apply"), "", e.jwtAdmin)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "task_duplicate") {
		t.Errorf("второй POST apply = %d %s, хочу 409 task_duplicate", rec.Code, rec.Body.String())
	}
	close(block)
	awaitState(t, e.tasks, taskID, taskSucceeded)
}

// TestRetentionPreviewProtections — причина защиты в отчёте: свежее
// обращение («access») и пин («pin») держат версию живой, кандидатом
// остаётся только незащищённая; apply удаляет ровно её.
func TestRetentionPreviewProtections(t *testing.T) {
	e := newRetentionEnv(t)
	// 7 версий, топ-3 защищены → 4 жертвы: из них одна посещалась,
	// вторая пинована, две — кандидаты.
	keys := e.seedVersions(t, 7)
	e.setPolicy(t, e.repoID, domain.Retention{MinVersions: 3, MaxAgeDays: 90})
	accessed, pinned, victim, spare := keys[0], keys[1], keys[2], keys[3]
	if err := e.access.MergeAccess(t.Context(), []domain.ObjectAccess{
		{Scope: domain.AccessScopeRepo, Key: accessed, LastAccess: e.clock.Now(), Hits: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := e.pin(t, http.MethodPut, versionTail(2), e.jwtAdmin); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT пин = %d, хочу 204 (тело %s)", rec.Code, rec.Body.String())
	}

	out, code := e.preview(t, e.repoID, e.jwtAdmin)
	if code != http.StatusOK {
		t.Fatalf("GET preview = %d, хочу 200", code)
	}
	if len(out.Candidates) != 4 {
		t.Fatalf("строк прогноза %d, хочу 4", len(out.Candidates))
	}
	byKey := map[string]RetentionCandidate{}
	for _, c := range out.Candidates {
		byKey[c.Key] = c
	}
	for key, want := range map[string]string{accessed: "access", pinned: "pin", victim: "", spare: ""} {
		if got := byKey[key].ProtectedBy; got != want {
			t.Errorf("protected_by %s = %q, хочу %q", key, got, want)
		}
	}
	if out.Totals.Candidates != 2 || out.Totals.ProtectedByAccess != 1 || out.Totals.ProtectedByPin != 1 {
		t.Errorf("итоги прогноза %+v, хочу candidates=2, access=1, pin=1", out.Totals)
	}

	taskID, code := e.apply(t, e.repoID, e.jwtAdmin)
	if code != http.StatusAccepted {
		t.Fatalf("POST apply = %d, хочу 202", code)
	}
	awaitState(t, e.tasks, taskID, taskSucceeded)
	for _, k := range []string{accessed, pinned} {
		if !gcHas(t, e.storage, k) {
			t.Errorf("защищённая версия %s удалена", k)
		}
	}
	for _, k := range []string{victim, spare} {
		if gcHas(t, e.storage, k) {
			t.Errorf("кандидат %s жив после apply", k)
		}
	}
}

// TestRetentionPins — пины под RequireRepoAccess: PUT существующего
// объекта → 204 (виден в списке полным ключом хранилища), PUT фантома →
// 404 (Stat), DELETE → 204 и пропажа из списка, scoped-токен своего репо
// проходит, чужого — 403; аудит pin/unpin под своими именами.
func TestRetentionPins(t *testing.T) {
	e := newRetentionEnv(t)
	keys := e.seedVersions(t, 2)
	pinsPath := e.path(e.repoID, "/retention/pins")
	tail := versionTail(1)

	rec := e.pin(t, http.MethodPut, tail, e.jwtAdmin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT пин = %d, хочу 204 (тело %s)", rec.Code, rec.Body.String())
	}
	if entry := lastAudit(t, e.audit); entry.Action != "repo.retention.pin" || entry.Result != domain.AuditOK {
		t.Errorf("аудит пина: %+v, хочу repo.retention.pin/ok", entry)
	}
	rec = e.call(t, http.MethodGet, pinsPath, "", e.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET pins = %d, хочу 200", rec.Code)
	}
	var got []string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != keys[0] {
		t.Fatalf("пины = %v, хочу [%s] (полный ключ хранилища)", got, keys[0])
	}

	// Фантом: объекта нет — пин бессмыслен (Stat → NotFound).
	rec = e.pin(t, http.MethodPut, versionTail(9), e.jwtAdmin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("PUT пин фантома = %d, хочу 404 (тело %s)", rec.Code, rec.Body.String())
	}
	// Пустой хвост — не ключ.
	rec = e.call(t, http.MethodPut, pinsPath+"/", "", e.jwtAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT пина с пустым ключом = %d, хочу 400", rec.Code)
	}

	// Владелец репо и scoped-токен своего репо — проходят.
	rec = e.call(t, http.MethodPut, pinsPath+"/"+versionTail(2), "", e.jwtUser)
	if rec.Code != http.StatusNoContent {
		t.Errorf("PUT пин владельцем = %d, хочу 204", rec.Code)
	}
	scoped := e.writeToken(t, e.ownerID, e.repoID)
	rec = e.call(t, http.MethodDelete, pinsPath+"/"+versionTail(2), "", scoped)
	if rec.Code != http.StatusNoContent {
		t.Errorf("DELETE пин scoped-токеном = %d, хочу 204", rec.Code)
	}
	if entry := lastAudit(t, e.audit); entry.Action != "repo.retention.unpin" || entry.Result != domain.AuditOK {
		t.Errorf("аудит анпина: %+v, хочу repo.retention.unpin/ok", entry)
	}

	// Чужой репо: scoped-токен другого репо — 403, не-владелец — 403.
	foreign := e.writeToken(t, e.ownerID, e.otherID)
	rec = e.call(t, http.MethodPut, pinsPath+"/"+versionTail(1), "", foreign)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT пин чужим токеном = %d, хочу 403", rec.Code)
	}
	rec = e.call(t, http.MethodPut, pinsPath+"/"+versionTail(1), "", e.jwtOther)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT пин не-владельцем = %d, хочу 403", rec.Code)
	}

	// Анпин: пина нет в списке.
	if rec := e.pin(t, http.MethodDelete, tail, e.jwtAdmin); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE пин = %d, хочу 204", rec.Code)
	}
	rec = e.call(t, http.MethodGet, pinsPath, "", e.jwtAdmin)
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("после анпина пины = %v, хочу пусто", got)
	}
}

// TestRetentionUnavailable — деградированный режим (нет движка): все пять
// маршрутов отвечают 503 retention_unavailable, а не 500/404 — фича
// честно выключена, а не «сломана».
func TestRetentionUnavailable(t *testing.T) {
	e := newRetentionEnv(t)
	handler := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: e.auth, SetupToken: "setup",
		Repos: e.repos, Storage: e.storage, Tasks: e.tasks, Clock: e.clock,
	})
	call := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "10.0.0.9:1"
		r.Header.Set("Authorization", "Bearer "+e.jwtAdmin)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, e.path(e.repoID, "/retention/preview")},
		{http.MethodPost, e.path(e.repoID, "/retention/apply")},
		{http.MethodGet, e.path(e.repoID, "/retention/pins")},
		{http.MethodPut, e.path(e.repoID, "/retention/pins/"+versionTail(1))},
		{http.MethodDelete, e.path(e.repoID, "/retention/pins/"+versionTail(1))},
	} {
		rec := call(tc.method, tc.path)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "retention_unavailable") {
			t.Errorf("%s %s = %d %s, хочу 503 retention_unavailable",
				tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}
