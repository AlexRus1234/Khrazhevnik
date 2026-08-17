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

import "time"

// Kind — изменчивость объекта upstream: immutable (deb/rpm-пакеты)
// кешируется навсегда, mutable (индексы, Release-файлы) — ревалидируется
// по conditional-запросам с TTL.
type Kind string

// Виды объектов.
const (
	KindImmutable Kind = "immutable"
	KindMutable   Kind = "mutable"
)

// Class — класс объекта: вид + период ревалидации для mutable.
// Живёт в domain, а не в port: классификация — предметная логика,
// адаптеры экосистем лишь возвращают готовые значения.
type Class struct {
	Kind Kind
	TTL  time.Duration // для mutable; у immutable игнорируется
}

// Immutable — класс неизменяемого объекта (кешируется навсегда).
func Immutable() Class { return Class{Kind: KindImmutable} }

// Mutable — класс изменяемого объекта с периодом ревалидации ttl.
func Mutable(ttl time.Duration) Class { return Class{Kind: KindMutable, TTL: ttl} }

// Validate проверяет согласованность класса: у mutable обязан быть
// положительный TTL.
func (c Class) Validate() error {
	if c.Kind != KindImmutable && c.Kind != KindMutable {
		return &ValidationError{What: "класс объекта", Value: string(c.Kind), Reason: "неизвестный вид"}
	}
	if c.Kind == KindMutable && c.TTL <= 0 {
		return &ValidationError{What: "класс объекта", Value: string(c.Kind), Reason: "mutable требует TTL > 0"}
	}
	return nil
}
