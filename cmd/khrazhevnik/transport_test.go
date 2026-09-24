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
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/testutil"
)

// TestDoerFactoryCacheIdentity — кеш по прокси-строке: повторный вызов
// с той же строкой отдаёт тот же клиент, разные строки — разные.
func TestDoerFactoryCacheIdentity(t *testing.T) {
	f := newDoerFactory(outboundHTTPClient(), nil)

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
	f := newDoerFactory(outboundHTTPClient(), nil)
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

	f := newDoerFactory(outboundHTTPClient(), nil)
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

	f := newDoerFactory(outboundHTTPClient(), nil)
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

// fakeProxySetting — port.UpstreamProxyStore в памяти: значение,
// счётчик чтений и инжектируемая ошибка (stale-if-error резолвера).
type fakeProxySetting struct {
	mu    sync.Mutex
	val   string
	err   error
	reads atomic.Int64
}

func (s *fakeProxySetting) UpstreamProxy(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads.Add(1)
	if s.err != nil {
		return "", s.err
	}
	return s.val, nil
}

func (s *fakeProxySetting) SetUpstreamProxy(_ context.Context, v string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.val = v
	return nil
}

// TestUpstreamProxyResolverTTL — ленивый кеш 30с: в пределах TTL
// значение из кеша (БД не перечитывается), после — перечитано.
func TestUpstreamProxyResolverTTL(t *testing.T) {
	store := &fakeProxySetting{val: "direct"}
	clock := testutil.NewManualClock(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	r := &upstreamProxyResolver{store: store, clock: clock}

	if got := r.current(); got != "direct" {
		t.Fatalf("первое чтение = %q, хочу direct", got)
	}
	store.mu.Lock()
	store.val = "socks5://h:1080"
	store.mu.Unlock()

	// +29с: TTL не исчерпан — кеш, БД молчит.
	clock.Advance(29 * time.Second)
	if got := r.current(); got != "direct" {
		t.Fatalf("в пределах TTL = %q, хочу cached direct", got)
	}
	if n := store.reads.Load(); n != 1 {
		t.Fatalf("чтений БД в пределах TTL = %d, хочу 1", n)
	}
	// +2с (итого 31с): TTL исчерпан — перечитано.
	clock.Advance(2 * time.Second)
	if got := r.current(); got != "socks5://h:1080" {
		t.Fatalf("после TTL = %q, хочу socks5://h:1080", got)
	}
	if n := store.reads.Load(); n != 2 {
		t.Fatalf("чтений БД после TTL = %d, хочу 2", n)
	}
}

// TestUpstreamProxyResolverStaleOnError — сбой чтения не роняет
// резолвер: отдаётся последнее известное значение, ошибка — в onError.
func TestUpstreamProxyResolverStaleOnError(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	store := &fakeProxySetting{val: "direct"}
	errSeen := make(chan error, 4)
	r := &upstreamProxyResolver{
		store: store, clock: clock,
		onError: func(err error) { errSeen <- err },
	}
	if got := r.current(); got != "direct" {
		t.Fatalf("первое чтение = %q, хочу direct", got)
	}
	store.mu.Lock()
	store.err = context.DeadlineExceeded
	store.mu.Unlock()
	clock.Advance(31 * time.Second)
	if got := r.current(); got != "direct" {
		t.Fatalf("при сбое БД = %q, хочу последнее известное direct", got)
	}
	select {
	case err := <-errSeen:
		if err == nil {
			t.Fatal("onError получил nil")
		}
	default:
		t.Fatal("onError не вызван при сбое чтения")
	}
}

// TestDoerFactoryResolverBranches — ветки резолва дефолтной строки:
// "" → env-клиент (def), "direct" → прямой, URL → проксированный;
// клиенты разделяются с явными вызовами DoerFor (общий кеш).
func TestDoerFactoryResolverBranches(t *testing.T) {
	store := &fakeProxySetting{val: ""}
	clock := testutil.NewManualClock(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	r := &upstreamProxyResolver{store: store, clock: clock}
	f, ok := newDoerFactory(outboundHTTPClient(), r.current).(*doerFactory)
	if !ok {
		t.Fatal("фабрика не *doerFactory")
	}
	// "" → env-ветка: тот же def, что и без резолвера.
	if got := f.DoerFor(""); got != f.def {
		t.Fatal("пустая настройка отдала не env-клиент")
	}
	// "direct" из настройки → тот же указатель, что явный DoerFor("direct").
	store.mu.Lock()
	store.val = "direct"
	store.mu.Unlock()
	clock.Advance(31 * time.Second)
	if got, want := f.DoerFor(""), f.DoerFor("direct"); got != want {
		t.Fatal("«direct» из настройки не разделил кеш с явным direct-клиентом")
	}
	// URL из настройки → тот же указатель, что явный DoerFor(url).
	store.mu.Lock()
	store.val = "socks5://h:1080"
	store.mu.Unlock()
	clock.Advance(31 * time.Second)
	if got, want := f.DoerFor(""), f.DoerFor("socks5://h:1080"); got != want {
		t.Fatal("URL из настройки не разделил кеш с явным socks5-клиентом")
	}
	if f.DoerFor("socks5://h:1080") == nil || f.DoerFor("") == f.def {
		t.Fatal("nil Doer для URL или откат URL-ветки в env-клиент")
	}
}

// TestDoerFactoryResolverSwitchesUpstream — сквозной факт: смена
// настройки применяется без рестарта — до TTL трафик идёт напрямую,
// после перечитывания — через новый прокси.
func TestDoerFactoryResolverSwitchesUpstream(t *testing.T) {
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

	store := &fakeProxySetting{val: "direct"}
	clock := testutil.NewManualClock(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	r := &upstreamProxyResolver{store: store, clock: clock}
	f := newDoerFactory(outboundHTTPClient(), r.current)

	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.DoerFor("").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if proxyHits.Load() != 0 {
		t.Fatalf("direct-клиент сходил через прокси: %d", proxyHits.Load())
	}

	// Смена настройки в БД видна только после исчерпания TTL.
	store.mu.Lock()
	store.val = proxy.URL
	store.mu.Unlock()
	clock.Advance(31 * time.Second)
	req2, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := f.DoerFor("").Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "proxy-marker" {
		t.Fatalf("тело не от прокси-сервера: %q", body)
	}
	if proxyHits.Load() < 1 {
		t.Fatal("запрос после смены настройки не дошёл до прокси")
	}
}
