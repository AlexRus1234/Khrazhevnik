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
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestDoerFactoryCacheIdentity — кеш по прокси-строке: повторный вызов
// с той же строкой отдаёт тот же клиент, разные строки — разные.
func TestDoerFactoryCacheIdentity(t *testing.T) {
	f := newDoerFactory(outboundHTTPClient())

	def1, def2 := f.DoerFor(""), f.DoerFor("")
	if def1 != def2 {
		t.Fatal("разные Doer для одной пустой строки")
	}
	direct1, direct2 := f.DoerFor("direct"), f.DoerFor("direct")
	if direct1 != direct2 {
		t.Fatal("разные Doer для одного «direct»")
	}
	if def1 == direct1 {
		t.Fatal("«direct» отдал дефолтный клиент (env-прокси остался)")
	}
	socks1, socks2 := f.DoerFor("socks5://h:1080"), f.DoerFor("socks5://h:1080")
	if socks1 != socks2 {
		t.Fatal("разные Doer для одного socks5-URL")
	}
	if socks1 == direct1 || socks1 == def1 {
		t.Fatal("socks5-URL отдал чужой клиент")
	}
}

// TestDoerFactorySocks5ClientCreated — создание клиента с socks5-схемой
// (нативная поддержка net/http) без паники; сетевое поведение socks
// не крыть (нужен socks-сервер) — валидация схемы остаётся в domain.
func TestDoerFactorySocks5ClientCreated(t *testing.T) {
	f := newDoerFactory(outboundHTTPClient())
	if f.DoerFor("socks5://user:pass@h:1080") == nil {
		t.Fatal("nil Doer для socks5 с userinfo")
	}
}

// TestDoerFactoryDirectBypassesProxy — «direct» ходит мимо прокси:
// ответ от целевого сервера, прокси запросов не видел.
func TestDoerFactoryDirectBypassesProxy(t *testing.T) {
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		_, _ = io.WriteString(w, "proxy-marker")
	}))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "target-marker")
	}))
	defer target.Close()

	f := newDoerFactory(outboundHTTPClient())
	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.DoerFor("direct").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "target-marker" {
		t.Fatalf("тело не от целевого сервера: %q", body)
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("прокси видел запросов: %d", proxyHits.Load())
	}
}

// TestDoerFactoryFixedProxyUsed — клиент с URL-прокси ходит через
// указанный прокси: запрос приходит на прокси-сервер.
func TestDoerFactoryFixedProxyUsed(t *testing.T) {
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		_, _ = io.WriteString(w, "proxy-marker")
	}))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "target-marker")
	}))
	defer target.Close()

	f := newDoerFactory(outboundHTTPClient())
	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.DoerFor(proxy.URL).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "proxy-marker" {
		t.Fatalf("тело не от прокси-сервера: %q", body)
	}
	if proxyHits.Load() < 1 {
		t.Fatal("запрос не дошёл до прокси-сервера")
	}
}
