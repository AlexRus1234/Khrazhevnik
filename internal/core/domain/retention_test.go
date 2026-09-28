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
	"testing"
)

func TestValidateRetention(t *testing.T) {
	cases := []struct {
		name    string
		r       Retention
		valid   bool
		enabled bool
	}{
		{"нулевая политика выключена", Retention{0, 0}, true, false},
		{"значения по умолчанию", Retention{3, 90}, true, true},
		{"отрицательный min_versions", Retention{-1, 0}, false, false},
		{"отрицательный max_age_days", Retention{3, -5}, false, true},
		{"keep=1 с возрастом — окно 404", Retention{1, 90}, false, true},
		{"возраст без гарантии минимума", Retention{0, 90}, false, false},
		{"keep=1 без возраста легален", Retention{1, 0}, true, true},
		{"только keep-N, возраст не задан", Retention{5, 0}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRetention(tc.r)
			if tc.valid {
				if err != nil {
					t.Fatalf("ValidateRetention(%+v) = %v, хочу nil", tc.r, err)
				}
			} else {
				if err == nil {
					t.Fatalf("ValidateRetention(%+v) = nil, хочу ValidationError", tc.r)
				}
				if !errors.Is(err, &ValidationError{}) {
					t.Fatalf("ValidateRetention(%+v) = %v, хочу ValidationError", tc.r, err)
				}
			}
			if got := tc.r.Enabled(); got != tc.enabled {
				t.Errorf("Retention%+v.Enabled() = %v, хочу %v", tc.r, got, tc.enabled)
			}
		})
	}
}
