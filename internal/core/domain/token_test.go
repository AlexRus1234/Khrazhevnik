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

import "testing"

func TestHashToken(t *testing.T) {
	// Эталонные векторы sha256.
	tests := []struct{ in, want string }{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, tc := range tests {
		if got := HashToken(tc.in); got != tc.want {
			t.Errorf("HashToken(%q) = %q, хочу %q", tc.in, got, tc.want)
		}
	}
}

func TestScopeAllowsWrite(t *testing.T) {
	tests := []struct {
		scope  Scope
		repoID int64
		want   bool
	}{
		{ScopeAdmin, 42, true},
		{"repo:42:write", 42, true},
		{"repo:42:write", 43, false},
		{"repo:0:write", 0, true},
		{"repo:42:read", 42, false},
		{"bogus", 42, false},
		{"", 42, false},
	}
	for _, tc := range tests {
		if got := tc.scope.AllowsWrite(tc.repoID); got != tc.want {
			t.Errorf("Scope(%q).AllowsWrite(%d) = %v, хочу %v", tc.scope, tc.repoID, got, tc.want)
		}
	}
}
