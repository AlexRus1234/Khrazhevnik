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

package main

import (
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"khrazhevnik/internal/core/port"
)

// doerFactory — port.DoerFactory с кешем клиентов по прокси-строке:
// один прокси — один клиент (и один пул соединений). Число различных
// прокси ≈ числу remote'ов, поэтому кеш без эвикции.
type doerFactory struct {
	mu      sync.RWMutex
	clients map[string]port.Doer
	def     port.Doer
}

// newDoerFactory строит фабрику транспортов. Tri-state proxyURL:
// "" — дефолтный Doer (env-прокси, текущее поведение), "direct" —
// транспорт без прокси, иначе URL прокси (http/https/socks5(h);
// userinfo URL — авторизация на прокси). Читаемая из БД глобальная
// настройка включается позже (сессия 156).
func newDoerFactory(defaultDoer port.Doer) port.DoerFactory {
	return &doerFactory{clients: map[string]port.Doer{}, def: defaultDoer}
}

// DoerFor возвращает клиента для прокси-строки, создавая его при
// первом обращении; повторные вызовы отдают тот же указатель.
func (f *doerFactory) DoerFor(proxyURL string) port.Doer {
	f.mu.RLock()
	c, ok := f.clients[proxyURL]
	f.mu.RUnlock()
	if ok {
		return c
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[proxyURL]; ok {
		// Второй создатель проиграл гонку — не дублируем клиента.
		return c
	}
	c = f.build(proxyURL)
	f.clients[proxyURL] = c
	return c
}

// build разбирает ветки tri-state. Ошибка парса невозможна после
// валидации remote (domain.ValidateProxyURL), но паранойя дешевле
// паники: невалидная строка — дефолтный клиент.
func (f *doerFactory) build(proxyURL string) port.Doer {
	switch proxyURL {
	case "":
		return f.def
	case "direct":
		return newProxyClient(nil)
	default:
		u, err := url.Parse(proxyURL)
		if err != nil {
			return f.def
		}
		return newProxyClient(func(*http.Request) (*url.URL, error) { return u, nil })
	}
}

// newProxyClient — транспорт с параметрами outboundHTTPClient, но с
// заменённым прокси. Таймауты и DisableCompression обязательны: тот же
// инвариант identity-запросов upstream (расжатие транспортом ломало бы
// byte-exact кеш) независимо от пути, которым идёт запрос.
func newProxyClient(proxy func(*http.Request) (*url.URL, error)) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 proxy,
			DisableCompression:    true,
			DialContext:           (&net.Dialer{Timeout: upstreamConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   upstreamConnectTimeout,
			ResponseHeaderTimeout: upstreamConnectTimeout,
		},
	}
}
