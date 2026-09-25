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

// Прокси upstream: валидация и маскирование Remote.ProxyURL.
// Семантика tri-state (решение владельца 2026-09-23): "" — наследовать
// глобальный прокси, ProxyDirect — явно без прокси, иначе URL.

package domain

import (
	"fmt"
	"net/url"
)

// ProxyDirect — sentinel-значение Remote.ProxyURL «ходить напрямую,
// глобальный прокси не применять». Точное слово, регистр важен:
// «Direct» — обычная невалидная строка.
const ProxyDirect = "direct"

// maxProxyURLLen — потолок длины URL прокси: достаточно для любого
// реального адреса с длинным userinfo, но отсекает мусорные простыни
// до того, как они уедут в БД и логи.
const maxProxyURLLen = 2048

// ValidateProxyURL проверяет значение Remote.ProxyURL: "" и
// ProxyDirect валидны тривиально; всё прочее обязано разобраться как
// URL со схемой строго из whitelist (isProxyScheme) и непустым host.
// Нарушение — *ValidationError{What: "прокси upstream"}.
func ValidateProxyURL(s string) error {
	if s == "" || s == ProxyDirect {
		return nil
	}
	if len(s) > maxProxyURLLen {
		return &ValidationError{
			What:   "прокси upstream",
			Value:  s,
			Reason: fmt.Sprintf("длиннее %d байт", maxProxyURLLen),
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return &ValidationError{
			What:   "прокси upstream",
			Value:  s,
			Reason: "не разбирается как URL",
		}
	}
	if !isProxyScheme(u.Scheme) {
		return &ValidationError{
			What:   "прокси upstream",
			Value:  s,
			Reason: fmt.Sprintf("схема %q, допустимы http/https/socks5/socks5h", u.Scheme),
		}
	}
	if u.Host == "" {
		return &ValidationError{
			What:   "прокси upstream",
			Value:  s,
			Reason: "пустой host",
		}
	}
	return nil
}

// isProxyScheme — whitelist схем прокси. switch вместо map: таблица
// известна на этапе компиляции, package-level мутабельное состояние
// не нужно. socks5h — resolve имени хоста на стороне прокси (внутри
// закрытого контура резолвер клиента ничего не видит).
func isProxyScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "socks5", "socks5h":
		return true
	}
	return false
}

// MaskProxyURL пересобирает URL прокси без userinfo:
// «socks5://u:p@h:1080» → «socks5://***@h:1080». Без userinfo строка
// возвращается как есть. Ошибка разбора или невалидный URL — тоже
// как есть: маскирование вызывают на пути логов/API и источником
// ошибок быть не должно (валидация — отдельная забота
// ValidateProxyURL).
func MaskProxyURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil || u.Host == "" {
		return s
	}
	return u.Scheme + "://***@" + u.Host
}
