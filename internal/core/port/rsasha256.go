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

// Порт xbps-подписи (RSA PKCS#1 v1.5 поверх SHA-256). Живёт ВНЕ
// port.Signer (тот заточен под OpenPGP/cleartext apt: InRelease +
// Release.gpg) — у xbps своя модель: для каждого пакета отдаётся
// detached-файл <pkg>.sig2 (сырые байты RSA-подписи), а публичный ключ
// встраивается в index-meta.plist. Реализация — mod/sign/rsasha256
// (сессия 139); инъекция в xbps RepoAdapter — через RsaSignerInjector
// (как NarSignerInjector для nix). wire (cmd) type-assert'ит адаптер к
// RsaSignerInjector и внедряет; nil = xbps-репо не подписываются.

package port

import "context"

// RsaSigner — источник RSA-подписи xbps. SignSHA256 принимает ровно
// 32-байтовый дайджест SHA-256 содержимого (нарушение длины — ошибка,
// не паника) и возвращает сырые байты подписи PKCS#1 v1.5 (512 для
// ключа 4096) — формат .sig2 (verifysig.c xbps-rindex). PublicKeyPEM
// отдаёт публичный ключ в SPKI-PEM (`PUBLIC KEY`) для index-meta.plist
// и ручки раздачи (сессия 142).
type RsaSigner interface {
	SignSHA256(ctx context.Context, digest []byte) ([]byte, error)
	PublicKeyPEM() ([]byte, error)
}

// RsaSignerInjector — опциональная способность RepoAdapter'а принять
// xbps-подписчик. wire type-assert'ит каждый собранный адаптер к этому
// интерфейсу и внедряет RsaSigner в поддерживающие (v1 — только xbps).
// Адаптеры без xbps-подписи не реализуют его — wire пропускает. Держим
// в port, т.к. это общий контракт генераторов, а не xbps-специфика
// (зеркально NarSignerInjector для nix).
type RsaSignerInjector interface {
	SetRsaSigner(s RsaSigner)
}
