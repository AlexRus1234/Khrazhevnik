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

import "fmt"

// Retention — политика ретеншна личного репозитория: сколько версий
// семейства гарантированно живы и какой порог давности обращения
// допускается. Нулевые поля — политика выключена (текущее поведение:
// репо растёт неограниченно в пределах квоты).
type Retention struct {
	// MinVersions — сколько версий семейства гарантированно живы
	// (def. 3 при включении; 0 — политика выключена).
	MinVersions int
	// MaxAgeDays — порог давности обращения к версии в сутках
	// (def. 90 при включении; 0 — без ограничения возраста).
	MaxAgeDays int
}

// Enabled — политика включена. Единственный переключатель —
// MinVersions: удаление без гарантии минимума запрещено (см.
// ValidateRetention).
func (r Retention) Enabled() bool { return r.MinVersions > 0 }

// ValidateRetention проверяет сочетание полей политики. Нарушение —
// *ValidationError{What: "политика ретеншна"}.
//
// Границы: MinVersions == 1 при заданном возрасте даёт окно 404
// (последняя версия может быть удалена по возрасту) — запрещено, как
// и в eviction кеш-прокси; MinVersions == 0 при заданном возрасте —
// «удалять всё старое без гарантии минимума» — тоже запрещено.
func ValidateRetention(r Retention) error {
	value := fmt.Sprintf("min_versions=%d, max_age_days=%d", r.MinVersions, r.MaxAgeDays)
	switch {
	case r.MinVersions < 0:
		return &ValidationError{What: "политика ретеншна", Value: value, Reason: "min_versions меньше нуля"}
	case r.MaxAgeDays < 0:
		return &ValidationError{What: "политика ретеншна", Value: value, Reason: "max_age_days меньше нуля"}
	case r.MinVersions == 1 && r.MaxAgeDays > 0:
		return &ValidationError{What: "политика ретеншна", Value: value, Reason: "min_versions=1 при заданном возрасте: последняя версия может быть удалена (окно 404)"}
	case r.MinVersions == 0 && r.MaxAgeDays > 0:
		return &ValidationError{What: "политика ретеншна", Value: value, Reason: "max_age_days без min_versions: политика без гарантии минимума"}
	}
	return nil
}
