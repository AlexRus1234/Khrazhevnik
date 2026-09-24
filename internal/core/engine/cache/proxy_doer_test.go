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

package cache

// Выбор Doer'а по прокси-строке Target (сессия 150): движок обязан
// спросить фабрику тем самым ProxyURL, что отдал Resolve, и отдать
// клиенту ответ как раньше — тело и статус не меняются.

import (
	"testing"

	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// recordingFactory — фейк-фабрика: записывает аргументы DoerFor,
// отдаёт fakeDoer с готовым 200-ответом (сети нет).
type recordingFactory struct {
	calls []string
	doer  port.Doer
}

// DoerFor фиксирует прокси-строку и возвращает заготовленный Doer.
func (f *recordingFactory) DoerFor(proxyURL string) port.Doer {
	f.calls = append(f.calls, proxyURL)
	return f.doer
}

// proxyEco — FakeEcosystem, каждый Target которого несёт заданную
// прокси-строку (будущий продукт адаптеров, сессия 152).
type proxyEco struct {
	testutil.FakeEcosystem
	proxy string
}

// Resolve делегирует и проставляет ProxyURL в Target.
func (e proxyEco) Resolve(ecosystemPath string) (port.Target, bool) {
	tgt, ok := e.FakeEcosystem.Resolve(ecosystemPath)
	if ok {
		tgt.ProxyURL = e.proxy
	}
	return tgt, ok
}

func TestDoerSelectedByTargetProxyURL(t *testing.T) {
	cases := []struct {
		name  string
		proxy string
	}{
		{name: "пустая — дефолтный путь", proxy: ""},
		{name: "direct — без прокси", proxy: "direct"},
		{name: "socks5 URL", proxy: "socks5://h:1080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := testutil.NewManualClock(testStart)
			factory := &recordingFactory{doer: newFakeDoer(-1, "payload")}
			engine := New(testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(), factory, clock, defaultConfig(), nil)
			eco := proxyEco{FakeEcosystem: testutil.FakeEcosystem{NameOf: "t", Base: "http://up.test", MutableTTL: 0}, proxy: tc.proxy}

			body, status, err := fetch(t, engine, eco, "/t/pkg/a.deb")
			if err != nil {
				t.Fatalf("fetch = %v, хочу успех", err)
			}
			if status != statusMiss {
				t.Fatalf("статус = %q, хочу MISS", status)
			}
			if body != "payload" {
				t.Fatalf("тело = %q, хочу payload", body)
			}
			if len(factory.calls) != 1 || factory.calls[0] != tc.proxy {
				t.Fatalf("DoerFor вызван с %v, хочу [%q]", factory.calls, tc.proxy)
			}
		})
	}
}

// повторный fetch того же объекта не дёргает фабрику — путь HIT
// минует upstream полностью.
func TestDoerFactoryNotCalledOnHit(t *testing.T) {
	clock := testutil.NewManualClock(testStart)
	factory := &recordingFactory{doer: newFakeDoer(-1, "payload")}
	engine := New(testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(), factory, clock, defaultConfig(), nil)
	eco := proxyEco{FakeEcosystem: testutil.FakeEcosystem{NameOf: "t", Base: "http://up.test", MutableTTL: 0}, proxy: "socks5://h:1080"}

	if _, _, err := fetch(t, engine, eco, "/t/pkg/a.deb"); err != nil {
		t.Fatalf("первый fetch = %v", err)
	}
	if _, status, err := fetch(t, engine, eco, "/t/pkg/a.deb"); err != nil || status != statusHit {
		t.Fatalf("второй fetch = %q, %v, хочу HIT", status, err)
	}
	if got := len(factory.calls); got != 1 {
		t.Fatalf("DoerFor вызван %d раз, хочу 1 (HIT без upstream)", got)
	}
}
