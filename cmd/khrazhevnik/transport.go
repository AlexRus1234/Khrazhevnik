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
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"khrazhevnik/internal/core/port"
)

// upstreamProxyTTL — лаг видимости смены глобальной настройки прокси
// (решение владельца 2026-09-23: применение без рестарта ≤30с).
const upstreamProxyTTL = 30 * time.Second

// upstreamProxyResolver — ленивый TTL-кеш значения upstream.proxy
// (паттерн remoteCache адаптеров): чтение БД не чаще раза в TTL.
// nil-стор — всегда "" (env-фолбэк). Сбой чтения не роняет трафик:
// отдаётся последнее известное значение (первый сбой — ""), ошибка
// уходит в onError (wire вешает лог).
type upstreamProxyResolver struct {
	store   port.UpstreamProxyStore
	clock   port.Clock
	onError func(error)

	mu       sync.RWMutex
	value    string
	lastRead time.Time
}

// current — значение настройки для фабрики: "" / "direct" / URL.
func (r *upstreamProxyResolver) current() string {
	if r == nil || r.store == nil {
		return ""
	}
	now := r.clock.Now()
	r.mu.RLock()
	fresh := now.Sub(r.lastRead) < upstreamProxyTTL
	v := r.value
	r.mu.RUnlock()
	if fresh {
		return v
	}
	got, err := r.store.UpstreamProxy(context.Background())
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastRead = now
	if err != nil {
		if r.onError != nil {
			r.onError(err)
		}
		return v
	}
	r.value = got
	return got
}

// doerFactory — port.DoerFactory с кешем клиентов по прокси-строке:
// один прокси — один клиент (и один пул соединений). Число различных
// прокси ≈ числу remote'ов плюс значения глобальной настройки, поэтому
// кеш без эвикции; смена настройки заводит новый клиент лишь после
// исчерпания TTL, старый остаётся в кеше.
type doerFactory struct {
	mu      sync.RWMutex
	clients map[string]port.Doer
	def     port.Doer
	// resolve — текущее значение глобальной настройки прокси; nil —
	// настройка не подключена, дефолтная ветка всегда env-клиент.
	resolve func() string
}

// newDoerFactory строит фабрику транспортов. Tri-state proxyURL:
// "" — дефолтный Doer (глобальная настройка из резолвера, при пустой —
// env-прокси), "direct" — транспорт без прокси, иначе URL прокси
// (http/https/socks5(h); userinfo URL — авторизация на прокси).
// resolve nil — поведение без настройки: "" всегда env-клиент.
func newDoerFactory(defaultDoer port.Doer, resolve func() string) port.DoerFactory {
	return &doerFactory{clients: map[string]port.Doer{}, def: defaultDoer, resolve: resolve}
}

// DoerFor возвращает клиента для прокси-строки, создавая его при
// первом обращении; повторные вызовы отдают тот же указатель.
func (f *doerFactory) DoerFor(proxyURL string) port.Doer {
	if proxyURL == "" && f.resolve != nil {
		proxyURL = f.resolve()
	}
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
