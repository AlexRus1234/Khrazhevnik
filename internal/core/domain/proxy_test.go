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

package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestValidateProxyURL(t *testing.T) {
	valid := []string{
		// Tri-state: наследование глобального и явный direct.
		"",
		ProxyDirect,
		// Все схемы, с портом и без.
		"http://proxy.local",
		"http://proxy.local:3128",
		"https://proxy.local:8443",
		"socks5://10.0.0.1:1080",
		"socks5://10.0.0.1",
		"socks5h://proxy.internal:1080",
		// Userinfo с паролем — легальны.
		"socks5://u:p@h:1080",
		"http://user:pa$$@proxy.local:3128",
		// Граница длины: ровно maxProxyURLLen проходит.
		"http://" + strings.Repeat("a", maxProxyURLLen-len("http://")),
	}
	for _, s := range valid {
		if err := ValidateProxyURL(s); err != nil {
			t.Errorf("ValidateProxyURL(%q) = %v, хочу nil", s, err)
		}
	}

	invalid := []string{
		// Регистр слова direct важен: это не sentinel.
		"Direct",
		"DIRECT",
		// Чужая схема.
		"ftp://h",
		// Ни схемы, ни чего-либо URL-подобного.
		"not-a-url",
		// Пустой host.
		"http://",
		"socks5://u:p@",
		// За границей длины.
		"http://" + strings.Repeat("a", maxProxyURLLen+1-len("http://")),
		// Не URL и не sentinel одним куском.
		ProxyDirect + " http://h",
	}
	for _, s := range invalid {
		err := ValidateProxyURL(s)
		if err == nil {
			t.Errorf("ValidateProxyURL(%q) = nil, хочу ошибку", s)
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("ValidateProxyURL(%q) = %T, хочу *ValidationError", s, err)
			continue
		}
		if ve.What != "прокси upstream" {
			t.Errorf("ValidateProxyURL(%q): What = %q, хочу «прокси upstream»", s, ve.What)
		}
	}
}

func TestMaskProxyURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"socks5://u:p@h:1080", "socks5://***@h:1080"},
		{"http://user:secret@proxy.local:3128", "http://***@proxy.local:3128"},
		// Только username без пароля — userinfo есть, маскируем тоже.
		{"socks5://u@h:1080", "socks5://***@h:1080"},
		// Без userinfo — строка не трогается.
		{"socks5://h:1080", "socks5://h:1080"},
		{"https://proxy.local:8443", "https://proxy.local:8443"},
		// Tri-state и мусор — без изменений, маскирование не источник
		// ошибок.
		{"", ""},
		{ProxyDirect, ProxyDirect},
		{"not-a-url", "not-a-url"},
		{ProxyDirect + " http://h", ProxyDirect + " http://h"},
		{"http://", "http://"},
	}
	for _, tc := range tests {
		if got := MaskProxyURL(tc.in); got != tc.want {
			t.Errorf("MaskProxyURL(%q) = %q, хочу %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskProxyURLKeepsHostPort(t *testing.T) {
	// Круглый: после маскирования host/port всех схем не искажаются —
	// маскированную строку можно отдать наружу без потери диагноза.
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		in := fmt.Sprintf("%s://admin:qwerty@example.test:1080", scheme)
		masked := MaskProxyURL(in)
		if strings.Contains(masked, "qwerty") {
			t.Errorf("MaskProxyURL(%q) = %q: пароль утёк", in, masked)
		}
		u, err := url.Parse(masked)
		if err != nil {
			t.Errorf("маскированный %q не разбирается: %v", masked, err)
			continue
		}
		if u.Scheme != scheme || u.Host != "example.test:1080" {
			t.Errorf("маскированный %q: scheme/host исказились: %s://%s", masked, u.Scheme, u.Host)
		}
	}
}
