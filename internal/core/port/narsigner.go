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

// Порт nix narinfo-подписи (ed25519). Живёт ВНЕ port.Signer (тот заточен
// под OpenPGP/cleartext apt: InRelease + Release.gpg) — у nix своя, более
// простая модель: sig-строка «name:pubkey:signature» (raw ed25519 +
// base64, не OpenPGP). Реализация — mod/sign/ed25519 (сессия 15);
// инъекция в nix RepoAdapter — через NarSignerInjector (как SignerInjector
// для apt). wire (cmd) type-assert'ит адаптер к NarSignerInjector и
// внедряет; nil = narinfo не переподписывается (сессия 16).

package port

// NarSigner — источник ed25519-подписи nix narinfo. Sign возвращает
// sig-строку формата «name:signature» (signature — base64 raw байт
// ed25519); msg — nix fingerprint «1;StorePath;NarHash;NarSize;Refs»
// (libstore PathInfo::fingerprint), собранный генератором из полей
// narinfo. PubKeyB64 — base64 публичной части для публикации в
// nix-метаданных (trusted-public-keys); Name — метка ключа.
type NarSigner interface {
	Sign(msg []byte) string
	PubKeyB64() string
	Name() string
}

// NarSignerInjector — опциональная способность RepoAdapter'а принять
// narinfo-подписчик. wire type-assert'ит каждый собранный адаптер к
// этому интерфейсу и внедряет NarSigner в поддерживающие (v1 — только
// nix). Адаптеры без narinfo-подписи не реализуют его — wire пропускает.
// Держим в port, т.к. это общий контракт генераторов, а не nix-специфика
// (зеркально SignerInjector для apt).
type NarSignerInjector interface {
	SetNarSigner(s NarSigner)
}
