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

// Eviction-поле remote переиспользует доменную политику Retention:
// значения валидируются ValidateRetention на входе API, nil —
// наследование глобального дефолта, валидации не подлежит.
func TestRemoteEvictionRetention(t *testing.T) {
	cases := []struct {
		name  string
		r     *Retention
		valid bool
	}{
		{"nil — наследовать глобальный дефолт", nil, true},
		{"явно выключено", &Retention{0, 0}, true},
		{"keep-N с возрастом", &Retention{2, 90}, true},
		{"keep=1 с возрастом — окно 404", &Retention{1, 90}, false},
		{"возраст без гарантии минимума", &Retention{0, 90}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rm := Remote{ID: 1, Name: "deb-main", Ecosystem: "apt", Eviction: tc.r}
			var err error
			if rm.Eviction != nil {
				err = ValidateRetention(*rm.Eviction)
			}
			if tc.valid {
				if err != nil {
					t.Fatalf("ValidateRetention(%+v) = %v, хочу nil", rm.Eviction, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateRetention(%+v) = nil, хочу ValidationError", rm.Eviction)
			}
			if !errors.Is(err, &ValidationError{}) {
				t.Fatalf("ValidateRetention(%+v) = %v, хочу ValidationError", rm.Eviction, err)
			}
		})
	}
}
