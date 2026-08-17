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
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	valid := []string{
		"cache/apt/1/pool/main/a/app/app_1.0_amd64.deb",
		"repo/7/apt/dists/stable/release",
		"tmp/00000000-0000-4000-8000-000000000000",
		"a",
		"0/9/_.-",
	}
	for _, key := range valid {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q) = %v, хочу nil", key, err)
		}
	}

	// Нападки: traversal, абсолютные пути, кодированные точки,
	// нулевые байты, windows-слэши, верхний регистр, URL-мусор.
	invalid := map[string]string{
		"":                               "пустой",
		"/abs/path":                      "ведущий слэш",
		"abs/":                           "хвостовой слэш",
		"..":                             "родитель",
		"a/../b":                         "traversal",
		"../etc/passwd":                  "traversal с файлом",
		"a..b":                           "двойная точка внутри сегмента",
		"a/./b":                          "текущий каталог",
		"a//b":                           "пустой сегмент",
		"%2e%2e/x":                       "кодированный traversal",
		"a/%2e%2e/b":                     "кодированный traversal в середине",
		"/x":                             "абсолютный",
		"cache/x\x00y":                   "нулевой байт",
		`C:\win\path`:                    "windows-путь",
		`\\server\share`:                 "UNC-путь",
		"Cache/UPPER":                    "верхний регистр",
		"cache/a?b":                      "URL-мусор",
		"cache/a b":                      "пробел",
		"объект":                         "не-ascii",
		strings.Repeat("a", maxKeyLen+1): "слишком длинный",
	}
	for key, why := range invalid {
		err := ValidateKey(key)
		if err == nil {
			t.Errorf("ValidateKey(%q) = nil, хочу ошибку (%s)", key, why)
			continue
		}
		var ik *InvalidKeyError
		if !errors.As(err, &ik) {
			t.Errorf("ValidateKey(%q) = %T, хочу *InvalidKeyError", key, err)
		}
	}
}

func TestValidateKeyJoinsReasons(t *testing.T) {
	// Несколько нарушений сразу: ведущий слэш + «..» + чужой символ.
	err := ValidateKey("/a../b?c")
	var ik *InvalidKeyError
	if !errors.As(err, &ik) {
		t.Fatalf("ожидался *InvalidKeyError, получили %T", err)
	}
	joined := 0
	for _, want := range []string{"ведущий", "..", "символ"} {
		if strings.Contains(err.Error(), want) {
			joined++
		}
	}
	if joined < 2 {
		t.Errorf("в %q перечислено %d нарушений, хочу сразу несколько: %v", err.Error(), joined, ik.Reasons)
	}
}

func TestValidateUsername(t *testing.T) {
	valid := []string{"alice", "a", "user-2", "u.v_w", "0root9", strings.Repeat("a", maxUsernameLen)}
	for _, name := range valid {
		if err := ValidateUsername(name); err != nil {
			t.Errorf("ValidateUsername(%q) = %v, хочу nil", name, err)
		}
	}
	invalid := map[string]string{
		"":                                    "пустое",
		"-alice":                              "начинается с дефиса",
		"alice-":                              "заканчивается дефисом",
		".bob":                                "начинается с точки",
		"bob.":                                "заканчивается точкой",
		"al..ice":                             "двойная точка",
		"AlIce":                               "верхний регистр",
		"al ice":                              "пробел",
		"алёна":                               "не-ascii",
		"a/b":                                 "слэш",
		strings.Repeat("a", maxUsernameLen+1): "слишком длинное",
	}
	for name, why := range invalid {
		err := ValidateUsername(name)
		if err == nil {
			t.Errorf("ValidateUsername(%q) = nil, хочу ошибку (%s)", name, why)
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("ValidateUsername(%q) = %T, хочу *ValidationError", name, err)
		}
	}
}

func TestValidateRepoName(t *testing.T) {
	if err := ValidateRepoName("my-repo"); err != nil {
		t.Errorf("ValidateRepoName(%q) = %v, хочу nil", "my-repo", err)
	}
	long := strings.Repeat("r", maxRepoNameLen+1)
	if err := ValidateRepoName(long); err == nil {
		t.Errorf("ValidateRepoName(%d байт) = nil, хочу ошибку", len(long))
	}
	// Username-подобные правила действуют и здесь.
	if err := ValidateRepoName("../evil"); err == nil {
		t.Error("ValidateRepoName(traversal) = nil, хочу ошибку")
	}
}

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		in   string
		want Scope
		ok   bool
	}{
		{"admin", ScopeAdmin, true},
		{"repo:7:write", "repo:7:write", true},
		{"repo:007:write", "repo:7:write", true}, // канонизация
		{"repo:0:write", "repo:0:write", true},
		{"repo:9223372036854775807:write", "repo:9223372036854775807:write", true},
		{"", "", false},
		{"Admin", "", false},
		{"admin ", "", false},
		{"write", "", false},
		{"repo:1:read", "", false},
		{"repo:abc:write", "", false},
		{"repo:-1:write", "", false},
		{"repo::write", "", false},
		{"repo:1:write:", "", false},
		{"repo:1:2:write", "", false},
		{"repo:9223372036854775808:write", "", false}, // переполнение uint63
		{" repo:1:write", "", false},
	}
	for _, tc := range tests {
		got, err := NormalizeScope(tc.in)
		if tc.ok {
			if err != nil {
				t.Errorf("NormalizeScope(%q) = %v, хочу %q", tc.in, err, tc.want)
				continue
			}
			if got != tc.want {
				t.Errorf("NormalizeScope(%q) = %q, хочу %q", tc.in, got, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("NormalizeScope(%q) = %q, хочу ошибку", tc.in, got)
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("NormalizeScope(%q) = %T, хочу *ValidationError", tc.in, err)
		}
	}
}
