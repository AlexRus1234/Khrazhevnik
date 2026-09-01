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
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestWarnAdminListen — предупреждение только для не-loopback адресов;
// дефолт :30202 (все интерфейсы) остаётся рабочим, но громким (аудит
// 2026-08-27).
func TestWarnAdminListen(t *testing.T) {
	cases := []struct {
		addr     string
		wantWarn bool
	}{
		{"127.0.0.1:30202", false},
		{"[::1]:30202", false},
		{"localhost:30202", false},
		{":30202", true},
		{"0.0.0.0:30202", true},
		{"[::]:30202", true},
		{"10.0.0.5:30202", true},
		{"admin.corp:30202", true},
	}
	for _, tc := range cases {
		buf := &bytes.Buffer{}
		warnAdminListen(slog.New(slog.NewTextHandler(buf, nil)), tc.addr)
		if got := buf.Len() > 0; got != tc.wantWarn {
			t.Errorf("warnAdminListen(%q): предупреждение = %v, хочу %v (лог %q)", tc.addr, got, tc.wantWarn, buf.String())
		}
	}
}

// TestNewLoggerBadLevel — опечатка KHRZ_LOG_LEVEL («debuge») видна:
// warning со значением и подсказкой допустимых уровней, затем info
// (аудит 2026-08-30, сессия 42). newLogger пишет в os.Stderr —
// подменяем на pipe и ждём flush (канал закрывается процессом).
func TestNewLoggerBadLevel(t *testing.T) {
	t.Setenv("KHRZ_LOG_LEVEL", "debuge")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	newLogger()
	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{"KHRZ_LOG_LEVEL", "debuge", "debug|info|warn|error"} {
		if !strings.Contains(got, want) {
			t.Errorf("в warning о log level нет %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("предупреждение должно быть level=WARN:\n%s", got)
	}
}
