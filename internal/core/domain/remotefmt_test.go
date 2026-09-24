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
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseRemoteLine(t *testing.T) {
	fullLine := "debian|apt|https://deb.debian.org/debian|mirror|socks5://u:p@h:1080|true|6h|stable,main"
	fullRemote := Remote{
		Name:         "debian",
		Ecosystem:    "apt",
		BaseURL:      "https://deb.debian.org/debian",
		Mode:         ModeMirror,
		ProxyURL:     "socks5://u:p@h:1080",
		Enabled:      true,
		SyncInterval: 6 * time.Hour,
		Include:      []string{"stable", "main"},
	}
	minimalLine := "fedora|rpm-md|https://dl.fedoraproject.org/pub/fedora/linux|proxy||false||"
	minimalRemote := Remote{
		Name:      "fedora",
		Ecosystem: "rpm-md",
		BaseURL:   "https://dl.fedoraproject.org/pub/fedora/linux",
		Mode:      ModeProxy,
		Enabled:   false,
	}

	tests := []struct {
		name    string
		line    string
		want    Remote
		wantOK  bool
		wantErr bool
	}{
		{name: "полная строка", line: fullLine, want: fullRemote, wantOK: true},
		{name: "минимальная строка", line: minimalLine, want: minimalRemote, wantOK: true},
		{name: "include с пробелами и пустыми", line: "deb|apt|https://h|proxy|direct|true|| stable , main ,, ", wantOK: true, want: Remote{
			Name: "deb", Ecosystem: "apt", BaseURL: "https://h", Mode: ModeProxy,
			ProxyURL: ProxyDirect, Enabled: true, Include: []string{"stable", "main"},
		}},
		{name: "интервал 2h", line: "a|apt|https://h|mirror|direct|true|2h|", wantOK: true, want: Remote{
			Name: "a", Ecosystem: "apt", BaseURL: "https://h", Mode: ModeMirror,
			ProxyURL: ProxyDirect, Enabled: true, SyncInterval: 2 * time.Hour,
		}},

		{name: "пустая строка", line: "", wantOK: false},
		{name: "строка из пробелов", line: "   ", wantOK: false},
		{name: "комментарий", line: "# comment", wantOK: false},
		{name: "комментарий в заголовке", line: "# name|ecosystem|base_url|mode|proxy|enabled|sync_interval|include", wantOK: false},

		{name: "семь полей", line: "a|apt|https://h|proxy|direct|true|2h", wantErr: true},
		{name: "девять полей", line: "a|apt|https://h|proxy|direct|true|2h|stable|extra", wantErr: true},
		{name: "пустое имя", line: "|apt|https://h|proxy|direct|true||", wantErr: true},
		{name: "пустая экосистема", line: "a||https://h|proxy|direct|true||", wantErr: true},
		{name: "пустой base_url", line: "a|apt||proxy|direct|true||", wantErr: true},
		{name: "режим cache", line: "a|apt|https://h|cache|direct|true||", wantErr: true},
		{name: "enabled 1", line: "a|apt|https://h|proxy|direct|1||", wantErr: true},
		{name: "интервал 2x", line: "a|apt|https://h|mirror|direct|true|2x|", wantErr: true},
		{name: "прокси ftp", line: "a|apt|https://h|proxy|ftp://h|true||", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := ParseRemoteLine(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseRemoteLine(%q) = nil, хочу ошибку", tc.line)
				}
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("ParseRemoteLine(%q) = %T, хочу *ValidationError", tc.line, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRemoteLine(%q) = %v, хочу nil", tc.line, err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ParseRemoteLine(%q): ok = %v, хочу %v", tc.line, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseRemoteLine(%q) = %+v, хочу %+v", tc.line, got, tc.want)
			}
		})
	}
}

func TestParseRemoteLineProxyValidation(t *testing.T) {
	// Сквозная проверка 149: невалидный прокси — не «общая ошибка
	// формата», а именно доменная ValidationError про прокси.
	_, _, err := ParseRemoteLine("a|apt|https://h|proxy|ftp://h|true||")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ParseRemoteLine = %T, хочу *ValidationError", err)
	}
	if ve.What != "прокси upstream" {
		t.Fatalf("What = %q, хочу «прокси upstream»", ve.What)
	}
}

func TestFormatRemoteRoundtrip(t *testing.T) {
	// Format→Parse без потерь. Byte-равенство к входной строке не
	// требуется: duration-поле нормализуется до канонического вида Go
	// («6h» → «6h0m0s»), а include — до join без пробелов. Потери
	// значения при этом нет — ремоут восстанавливается по полям.
	remotes := []Remote{
		{
			Name: "debian", Ecosystem: "apt", BaseURL: "https://deb.debian.org/debian",
			Mode: ModeMirror, ProxyURL: "socks5://u:p@h:1080", Enabled: true,
			SyncInterval: 6 * time.Hour, Include: []string{"stable", "main"},
		},
		{
			Name: "fedora", Ecosystem: "rpm-md", BaseURL: "https://dl.fedoraproject.org/pub/fedora/linux",
			Mode: ModeProxy, Enabled: false,
		},
		{
			Name: "arch", Ecosystem: "pacman", BaseURL: "https://mirror.example.test/archlinux",
			Mode: ModeMirror, ProxyURL: ProxyDirect, Enabled: true,
			SyncInterval: 2 * time.Hour, Include: []string{"core", "extra"},
		},
	}
	for _, r := range remotes {
		line := FormatRemote(r)
		got, ok, err := ParseRemoteLine(line)
		if err != nil || !ok {
			t.Fatalf("ParseRemoteLine(FormatRemote(%+v)=%q): ok=%v err=%v", r, line, ok, err)
		}
		if !reflect.DeepEqual(got, r) {
			t.Errorf("круглый FormatRemote → ParseRemoteLine = %+v, хочу %+v", got, r)
		}
	}
}

func TestFormatRemotesRoundtrip(t *testing.T) {
	want := []Remote{
		{
			Name: "debian", Ecosystem: "apt", BaseURL: "https://deb.debian.org/debian",
			Mode: ModeMirror, ProxyURL: "socks5://u:p@h:1080", Enabled: true,
			SyncInterval: 6 * time.Hour, Include: []string{"stable", "main"},
		},
		{
			Name: "fedora", Ecosystem: "rpm-md", BaseURL: "https://dl.fedoraproject.org/pub/fedora/linux",
			Mode: ModeProxy, Enabled: false,
		},
	}

	out := FormatRemotes(want)
	if !strings.HasPrefix(out, "# khrazhevnik remotes export v1\n") {
		t.Fatalf("FormatRemotes: нет заголовка:\n%s", out)
	}

	var got []Remote
	for _, line := range strings.Split(out, "\n") {
		r, ok, err := ParseRemoteLine(line)
		if err != nil {
			t.Fatalf("ParseRemoteLine(%q) = %v", line, err)
		}
		if ok {
			got = append(got, r)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("круглый FormatRemotes → ParseRemoteLine = %+v, хочу %+v", got, want)
	}
}

func TestFormatRemotesEmpty(t *testing.T) {
	out := FormatRemotes(nil)
	if !strings.HasPrefix(out, "# khrazhevnik remotes export v1\n") {
		t.Fatalf("FormatRemotes(nil): нет заголовка:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		_, ok, err := ParseRemoteLine(line)
		if err != nil {
			t.Fatalf("ParseRemoteLine(%q) = %v", line, err)
		}
		if ok {
			t.Fatalf("FormatRemotes(nil): неожиданная значимая строка %q", line)
		}
	}
}
