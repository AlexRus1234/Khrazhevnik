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

// Валидация входа админ-API. Канон значений — в domain.Validate*
// (предикаты + нормализация); здесь — тонкая HTTP-обёртка: парсит тело,
// гоняет через domain-валидаторы и собирает все проблемы в один
// snake_case-код ошибки (фронт маппит в i18n, сессия 18).
//
// Подход как в Intermasq/internal/validate: unexported regex/предикаты
// живут в domain, здесь — только вызовы и нормализация перед мутацией.

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"khrazhevnik/internal/core/domain"
)

// apiError — единое тело ошибки API: {"error":"snake_case_code"}.
// Фронтенд (сессия 18) маппит код в локализованное сообщение.
type apiError struct {
	Code string `json:"error"`
}

// writeErr пишет snake_case-код ошибки. Маппинг domain-ошибок на коды
// централизован в statusFor: ни один хендлер не решает код сам.
func writeErr(w http.ResponseWriter, err error) {
	status, code := statusFor(err)
	writeJSON(w, status, apiError{Code: code})
}

// writeErrCode пишет явный код с вычисленным статусом — для проверок,
// где ошибки нет (например, «не найдено» по URL-параметру).
func writeErrCode(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, apiError{Code: code})
}

// statusFor маппит domain-ошибку на HTTP-статус и snake_case-код.
// Централизованная точка: все хендлеры идут через неё, ни один не
// придумывает коды самостоятельно.
func statusFor(err error) (int, string) {
	var nf *domain.NotFoundError
	var conf *domain.ConflictError
	var forb *domain.ForbiddenError
	var val *domain.ValidationError
	var tooLarge *domain.TooLargeError
	var stale *domain.StaleError
	var quota *domain.QuotaExceededError
	var unsup *domain.UnsupportedError
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.As(err, &nf):
		return http.StatusNotFound, "not_found"
	case errors.As(err, &conf):
		return http.StatusConflict, "conflict"
	case errors.As(err, &forb):
		return http.StatusForbidden, "forbidden"
	case errors.As(err, &val):
		return http.StatusBadRequest, "validation_error"
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, "too_large"
	case errors.As(err, &quota):
		// 413 Payload Too Large: квота — сумма по репо; 507 Insufficient
		// Storage тоже подходит, но 413 даёт явный сигнал «слишком много»
		// и не конфликтует с webdav-семантикой.
		return http.StatusRequestEntityTooLarge, "quota_exceeded"
	case errors.As(err, &stale):
		return http.StatusConflict, "stale"
	case errors.As(err, &unsup):
		return http.StatusNotImplemented, "unsupported"
	case errors.Is(err, ErrTaskDuplicate):
		return http.StatusConflict, "task_duplicate"
	case errors.Is(err, ErrTaskLimit):
		return http.StatusTooManyRequests, "task_limit"
	}
	return http.StatusInternalServerError, "internal"
}

// maxJSONBody — потолок JSON-тела админ-API. Все декодируемые тела —
// учётные данные и настройки (килобайты); 1 MiB закрывает OOM-вектор
// «одна строка в десятки ГБ на анонимном /setup или /auth/login»
// (аудит 2026-08-27): память не аллоцируется сверх лимита, соединение
// закрывается сервером.
const maxJSONBody = 1 << 20

// decodeJSON парсит тело запроса в v. Пустое тело — BadRequest с кодом
// invalid_json (кроме случаев, где пустое тело валидно — там хендлер
// обходится без decodeJSON). Превышение maxJSONBody — 413
// payload_too_large: клиентская ошибка, а не OOM сервера.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErrCode(w, http.StatusRequestEntityTooLarge, "payload_too_large")
			return false
		}
		writeErrCode(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

// parseInt64URLParam достаёт {name} из URL и парсит в int64. Невалидный
// или отсутствующий — NotFound: ресурс с таким ID не существует.
func parseInt64URLParam(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := urlParam(r, name)
	if raw == "" {
		writeErrCode(w, http.StatusNotFound, "not_found")
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeErrCode(w, http.StatusNotFound, "not_found")
		return 0, false
	}
	return id, true
}

// parseInt64Query достаёт числовой query-параметр; пустое или
// нечисловое значение → fallback. Для опциональных параметров
// пагинации/лимита.
func parseInt64Query(r *http.Request, name string, fallback int64) int64 {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

// urlParam — обёртка над chi.URLParam, чтобы validate.go не тянул chi
// в импорты (для тестов middleware достаточно).
func urlParam(r *http.Request, name string) string {
	// chi.URLParam живёт в роутере; здесь — через контекст chi, но
	// чтобы не плодить зависимостей, дёргаем helpers.go (см. ниже).
	return chiURLParam(r, name)
}

// validateRemoteInput проверяет поля remote из запроса. name — slug
// (domain.ValidateUsername с теми же правилами, что и имя юзера:
// remote-имя живёт в URL и путях кеша,的限制 одинаковые). base_url —
// обязательно http(s)://. mode — proxy|mirror. sync_interval —
// положительная duration (0 = только вручную).
type remoteInput struct {
	Name         string        `json:"name"`
	Ecosystem    string        `json:"ecosystem"`
	BaseURL      string        `json:"base_url"`
	Mode         string        `json:"mode"`
	Enabled      *bool         `json:"enabled"`
	SyncInterval time.Duration `json:"sync_interval"`
	Include      []string      `json:"include"`
}

// validate проверяет поля remoteInput и возвращает первую ошибку
// домена (для statusFor). Нормализация: name и ecosystem — нижний
// регистр, base_url — без хвостового «/».
func (in *remoteInput) validate() error {
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Ecosystem = strings.ToLower(strings.TrimSpace(in.Ecosystem))
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	if err := domain.ValidateUsername(in.Name); err != nil {
		return err
	}
	if in.Ecosystem == "" {
		return &domain.ValidationError{What: "экосистема", Value: in.Ecosystem, Reason: "пусто"}
	}
	if !isHTTPURL(in.BaseURL) {
		return &domain.ValidationError{What: "base_url", Value: in.BaseURL, Reason: "ожидался http(s):// URL"}
	}
	switch domain.RemoteMode(in.Mode) {
	case domain.ModeProxy, domain.ModeMirror:
	default:
		return &domain.ValidationError{What: "mode", Value: in.Mode, Reason: "ожидалось proxy|mirror"}
	}
	if in.SyncInterval < 0 {
		return &domain.ValidationError{What: "sync_interval", Value: in.SyncInterval.String(), Reason: "не может быть отрицательным"}
	}
	return nil
}

// isHTTPURL сообщает, выглядит ли s как абсолютный http(s):// URL.
// Полная проверка оставлена upstream-клиенту: запрос к невалидному
// хосту даст transport error, а парсинг здесь — только отсеивает
// откровенный мусор.
func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
