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

// Signer — источник подписи метаданных личного репозитория. Реализации
// — mod/sign/openpgp (apt/rpm-md/pacman/apk: InRelease + Release.gpg)
// и mod/sign/ed25519 (nix narinfo, сессия 16).
//
// Sign возвращает cleartext-подпись input: читаемый текст с встроенной
// OpenPGP-подписью (формат InRelease apt — apt-get update умеет только
// такой inline-формат). Input вычитывается полностью: cleartext
// требует знания всего сообщения перед эмиссией dash-escaped блока.
//
// SignDetached возвращает отдельную (detached) подпись input — бинарный
// OpenPGP-сигнатурный пакет (формат Release.gpg apt: бинарный, не
// armored — apt парсит именно бинарный). Потоковый: input передаётся
// в подписант напрямую, без полной буферизации.
//
// PublicKey — armored публичный ключ для раздачи клиентам через
// GET /repo/<name>/key.asc (публичный порт :29202).
type Signer interface {
	Sign(ctx context.Context, input io.Reader) (io.Reader, error)
	SignDetached(ctx context.Context, input io.Reader) (io.Reader, error)
	PublicKey() ([]byte, error)
}
