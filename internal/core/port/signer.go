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

// Порт подписи метаданных личных репозиториев. Конкретика (OpenPGP,
// ed25519) — модули mod/sign/*, сессия 15.

package port

import (
	"context"
	"io"
)

// Signer — источник detached/inline-подписи метаданных. Sign читает
// input полностью и возвращает ридер с подписанными данными;
// PublicKey — публичный ключ в формате реализации (armored OpenPGP
// или база64 ed25519) для отдачи клиентам.
type Signer interface {
	Sign(ctx context.Context, input io.Reader) (io.Reader, error)
	PublicKey() ([]byte, error)
}
