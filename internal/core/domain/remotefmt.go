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

// Построчный формат источников (remote) для импорта/экспорта:
// табличный текст, одна строка — один remote, поля через «|». Формат
// зафиксирован при планировании (решение владельца 2026-09-23) и
// является контрактом с API-слоем: имя-строки-с-номером и обвязку
// файла сюда не тащим.

package domain

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// remotesExportHeader — двухстрочный заголовок экспорта. Строки
// начинаются с «#»: ParseRemoteLine пропускает их как комментарии, так
// заголовок читается и человеком, и этим же парсером.
const remotesExportHeader = "# khrazhevnik remotes export v1\n" +
	"# name|ecosystem|base_url|mode|proxy|enabled|sync_interval|include\n"

// remotesFieldCount — число полей строки источника: name, ecosystem,
// base_url, mode, proxy, enabled, sync_interval, include.
const remotesFieldCount = 8

// ParseRemoteLine разбирает одну строку табличного формата источников.
// false возвращается для строки-пропуска (пустая после trim или
// комментарий «#...») — это не ошибка. Для значимой строки требуется
// ровно remotesFieldCount полей; любое нарушение — *ValidationError.
// CreatedAt не заполняется: ноль оставляет БД поставить время записи.
// Номер строки в ошибку не кладётся — контекст файла знает API-слой.
func ParseRemoteLine(s string) (Remote, bool, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return Remote{}, false, nil
	}

	fields := strings.Split(s, "|")
	if len(fields) != remotesFieldCount {
		return Remote{}, false, &ValidationError{
			What:   "строка источника",
			Value:  s,
			Reason: fmt.Sprintf("ожидалось %d полей, получено %d", remotesFieldCount, len(fields)),
		}
	}

	name, ecosystem, baseURL := fields[0], fields[1], fields[2]
	for _, required := range []struct{ what, value string }{
		{"имя источника", name},
		{"экосистема источника", ecosystem},
		{"base_url источника", baseURL},
	} {
		if required.value == "" {
			return Remote{}, false, &ValidationError{
				What:   "строка источника",
				Value:  s,
				Reason: required.what + " пусто",
			}
		}
	}

	mode := RemoteMode(fields[3])
	if mode != ModeProxy && mode != ModeMirror {
		return Remote{}, false, &ValidationError{
			What:   "строка источника",
			Value:  s,
			Reason: fmt.Sprintf("режим %q, допустимы %s/%s", fields[3], ModeProxy, ModeMirror),
		}
	}

	proxy := fields[4]
	if err := ValidateProxyURL(proxy); err != nil {
		return Remote{}, false, err
	}

	enabled, err := parseRemoteEnabled(fields[5], s)
	if err != nil {
		return Remote{}, false, err
	}
	interval, err := parseRemoteInterval(fields[6], s)
	if err != nil {
		return Remote{}, false, err
	}

	return Remote{
		Name:         name,
		Ecosystem:    ecosystem,
		BaseURL:      baseURL,
		Mode:         mode,
		Enabled:      enabled,
		SyncInterval: interval,
		Include:      parseRemoteInclude(fields[7]),
		ProxyURL:     proxy,
	}, true, nil
}

// parseRemoteEnabled разбирает поле enabled строки источника: строго
// «true»/«false», без синонимов и регистра.
func parseRemoteEnabled(value, line string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, &ValidationError{
		What:   "строка источника",
		Value:  line,
		Reason: fmt.Sprintf("enabled %q, допустимы true/false", value),
	}
}

// parseRemoteInterval разбирает поле sync_interval: пусто — 0 (только
// ручной sync), иначе Go duration-строка.
func parseRemoteInterval(value, line string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, &ValidationError{
			What:   "строка источника",
			Value:  line,
			Reason: fmt.Sprintf("sync_interval %q: %v", value, err),
		}
	}
	return d, nil
}

// parseRemoteInclude разбирает include-фильтры: поле через запятую,
// элементы trim'ятся, пустые отбрасываются. Пустое поле — nil (не
// пустой срез): «sync всего» отличается от «явно ничего».
func parseRemoteInclude(value string) []string {
	if value == "" {
		return nil
	}
	var include []string
	for _, part := range strings.Split(value, ",") {
		if p := strings.TrimSpace(part); p != "" {
			include = append(include, p)
		}
	}
	return include
}

// FormatRemote собирает строку источника из Remote — обратная к
// ParseRemoteLine. Нулевой SyncInterval пишется пустым полем (0 — «только
// ручной sync»), ProxyURL — как есть (в том числе ""/direct). ID и
// CreatedAt в формат не входят: они локальны для инстанса.
func FormatRemote(r Remote) string {
	interval := ""
	if r.SyncInterval != 0 {
		interval = r.SyncInterval.String()
	}
	return strings.Join([]string{
		r.Name,
		r.Ecosystem,
		r.BaseURL,
		string(r.Mode),
		r.ProxyURL,
		strconv.FormatBool(r.Enabled),
		interval,
		strings.Join(r.Include, ","),
	}, "|")
}

// FormatRemotes собирает полный файл экспорта: заголовок и по строке на
// каждый remote. Пустой список даёт только заголовок. Вывод пригоден к
// повторному разбору ParseRemoteLine построчно (комментарии
// пропускаются).
func FormatRemotes(rs []Remote) string {
	var b strings.Builder
	b.WriteString(remotesExportHeader)
	for _, r := range rs {
		b.WriteString(FormatRemote(r))
		b.WriteByte('\n')
	}
	return b.String()
}
