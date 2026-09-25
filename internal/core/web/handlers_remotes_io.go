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

// Табличный экспорт/импорт источников (сессия 159): GET /remotes/export
// отдаёт текстовый файл формата domain.FormatRemotes, POST
// /remotes/import строит отчёт {created, skipped, errors} построчным
// разбором. Семантика дублей — «пропускать с отчётом» (решение
// владельца 2026-09-23): валидные строки создаются, битые репортятся,
// транзакции на весь файл нет.

package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"khrazhevnik/internal/core/domain"
)

// remotesImportMaxBody — потолок тела импорта: таблица источников —
// килобайты, 256 KiB закрывают вектор «гигантское тело на admin-роут».
const remotesImportMaxBody = 256 << 10

// remotesImportMaxLines — потолок числа строк: отчёт об ошибках
// ограничен, 1000 источников на инстанс с запасом.
const remotesImportMaxLines = 1000

// importSkip — пропущенная строка: номер (1-based) и имя.
type importSkip struct {
	Line int    `json:"line"`
	Name string `json:"name"`
}

// importError — битая строка: номер, snake_case-код и короткая причина.
type importError struct {
	Line   int    `json:"line"`
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// importReport — тело ответа POST /remotes/import. Срезы инициализируются
// пустыми: SPA ждёт [], а не null.
type importReport struct {
	Created []string      `json:"created"`
	Skipped []importSkip  `json:"skipped"`
	Errors  []importError `json:"errors"`
}

// handleExportRemotes — GET /api/v1/remotes/export: текстовый файл
// источников. Порядок строк — порядок каталога (по возрастанию ID); файл
// пригоден к повторному разбору импортом.
func handleExportRemotes(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rs, err := d.Remotes.Remotes(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="khrazhevnik-remotes.txt"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, domain.FormatRemotes(rs))
	}
}

// handleImportRemotes — POST /api/v1/remotes/import: построчный разбор.
// Всегда 200 при разобранном теле, даже с ошибками строк (частичный
// успех): валидные строки создаются, дубли (в БД или внутри файла) и
// битые строки — в отчёт. 400/413 — только если разобрать нечего
// (слишком длинное тело или >1000 строк).
func handleImportRemotes(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Action сразу: аудит обязан писать remote.import и для
		// отклонённого импорта (413/400), не fallback-именем роута.
		*r = *r.WithContext(WithAuditAction(r.Context(), "remote.import"))

		r.Body = http.MaxBytesReader(w, r.Body, remotesImportMaxBody)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeErrCode(w, http.StatusRequestEntityTooLarge, "payload_too_large")
				return
			}
			writeErrCode(w, http.StatusBadRequest, "invalid_body")
			return
		}

		lines := strings.Split(string(data), "\n")
		// Хвостовой перевод строки не считаем отдельной строкой: экспорт
		// заканчивается «\n», и файл без него не должен резаться лимитом.
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
		if len(lines) > remotesImportMaxLines {
			writeErrCode(w, http.StatusBadRequest, "import_too_many")
			return
		}

		created := []string{}
		skipped := []importSkip{}
		lineErrors := []importError{}
		seen := make(map[string]bool)

		for i, raw := range lines {
			lineNo := i + 1
			rem, ok, perr := domain.ParseRemoteLine(raw)
			if !ok {
				if perr != nil {
					lineErrors = append(lineErrors, importError{
						Line: lineNo, Code: "validation_error", Reason: validationReason(perr),
					})
				}
				continue
			}
			// Нормализация как в JSON-пути (handleCreateRemote): без неё
			// «Debian» из файла создал бы remote, неотличимый от дубля
			// «debian» и не совпадающий с slug-правилами.
			rem.Name = strings.ToLower(strings.TrimSpace(rem.Name))
			rem.Ecosystem = strings.ToLower(strings.TrimSpace(rem.Ecosystem))
			rem.BaseURL = strings.TrimRight(strings.TrimSpace(rem.BaseURL), "/")
			if verr := validateRemoteSpec(remoteSpec{
				Name: rem.Name, Ecosystem: rem.Ecosystem, BaseURL: rem.BaseURL,
				Mode: string(rem.Mode), SyncInterval: rem.SyncInterval, ProxyURL: rem.ProxyURL,
			}); verr != nil {
				lineErrors = append(lineErrors, importError{
					Line: lineNo, Code: "validation_error", Reason: validationReason(verr),
				})
				continue
			}
			if seen[rem.Name] {
				skipped = append(skipped, importSkip{Line: lineNo, Name: rem.Name})
				continue
			}
			rem.CreatedAt = d.clock().Now()
			if _, err := d.Remotes.CreateRemote(r.Context(), rem); err != nil {
				var conf *domain.ConflictError
				if errors.As(err, &conf) {
					// Дубль уже в БД — пропуск с отчётом, не 409 на весь файл.
					skipped = append(skipped, importSkip{Line: lineNo, Name: rem.Name})
					continue
				}
				// Сбой каталога — импорт не может продолжаться: отдаём
				// реальную ошибку, уже созданные строки остаются в БД
				// (транзакции на весь файл нет по решению владельца).
				writeErr(w, err)
				return
			}
			seen[rem.Name] = true
			created = append(created, rem.Name)
		}

		if len(created) > 0 {
			d.notifyRemotesChanged()
		}
		*r = *r.WithContext(WithAuditDetail(r.Context(),
			fmt.Sprintf(`{"created":%d,"skipped":%d,"errors":%d}`, len(created), len(skipped), len(lineErrors))))
		writeJSON(w, http.StatusOK, importReport{Created: created, Skipped: skipped, Errors: lineErrors})
	}
}

// validationReason достаёт короткую причину ValidationError для отчёта
// об ошибке строки; иная ошибка — пустая причина (код всё равно несёт
// смысл).
func validationReason(err error) string {
	var v *domain.ValidationError
	if errors.As(err, &v) {
		return v.Reason
	}
	return ""
}
