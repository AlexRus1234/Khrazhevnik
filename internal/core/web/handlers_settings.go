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

// Хендлеры глобальных настроек инстанса (/api/v1/settings, сессия 156).
// Тонкие: парс → порт → writeJSON/writeErr, коды — через statusFor.
// Применение значения на исходящих запросах — забота фабрики Doer'ов
// в wire (ленивый TTL-кеш 30с), хендлер только читает/пишет стор.

package web

import (
	"fmt"
	"net/http"

	"khrazhevnik/internal/core/domain"
)

// upstreamProxyValue — тело GET/PUT /settings/upstream-proxy: ""
// (не задано — env-фолбэк), "direct" или URL прокси.
type upstreamProxyValue struct {
	Value string `json:"value"`
}

// handleGetUpstreamProxy — GET /api/v1/settings/upstream-proxy: 200
// {"value": v}; пустая БД — "". Чтение без аудита (прецедент /tasks,
// /cache/stats).
func handleGetUpstreamProxy(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Settings == nil {
			// Деградированный режим: настройка не задана — пустое
			// значение честно (поведение = env-фолбэк).
			writeJSON(w, http.StatusOK, upstreamProxyValue{})
			return
		}
		v, err := d.Settings.UpstreamProxy(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, upstreamProxyValue{Value: v})
	}
}

// handlePutUpstreamProxy — PUT /api/v1/settings/upstream-proxy: тело
// {"value": s}; "" и "direct" валидны тривиально, прочее — через
// domain.ValidateProxyURL (иначе 400 validation_error). 200 {"value": s}.
// Пароль прокси в аудит не течёт: detail несёт только маску
// (domain.MaskProxyURL, сессия 149).
func handlePutUpstreamProxy(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Settings == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "settings_unavailable")
			return
		}
		var in upstreamProxyValue
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Value != "" && in.Value != domain.ProxyDirect {
			if err := domain.ValidateProxyURL(in.Value); err != nil {
				writeErr(w, err)
				return
			}
		}
		// Action до мутации (урок сессии 87): отклонённая запись видна
		// в трейле под settings.update, а не fallback-именем.
		*r = *r.WithContext(WithAuditAction(r.Context(), "settings.update"))
		*r = *r.WithContext(WithAuditDetail(r.Context(),
			fmt.Sprintf(`{"value":%q}`, domain.MaskProxyURL(in.Value))))
		if err := d.Settings.SetUpstreamProxy(r.Context(), in.Value, d.clock().Now()); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, upstreamProxyValue{Value: in.Value})
	}
}
