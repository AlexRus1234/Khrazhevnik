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

// Package migrations — SQL-миграции postgres-каталога (диалект-
// специфичный каталог migrations/<driver>/ — docs/SPECIFICATION.md
// §БД). FS — package-level var: go:embed иначе не работает, а значение
// compile-time иммутабельно (то же обоснование исключения, что у
// закрытого состояния internal/core/registry — см. AGENTS.md).
package migrations

import "embed"

// FS — встроенные миграции goose; файлы лежат в корне каталога и видны
// провайдеру без подкаталогов.
//
//go:embed *.sql
var FS embed.FS
