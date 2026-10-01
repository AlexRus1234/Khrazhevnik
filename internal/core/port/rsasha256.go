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

// Порт RSA-подписи (RSA PKCS#1 v1.5). Живёт ВНЕ
// port.Signer (тот заточен под OpenPGP/cleartext apt: InRelease +
// Release.gpg) — у xbps своя модель: для каждого пакета отдаётся
// detached-файл <pkg>.sig2 (сырые байты RSA-подписи; штатная подпись
// xbps-rindex) и <pkg>.sig (легаси-подпись Void — та же подпись, но с
// SHA-1-DigestInfo вокруг SHA-256-дайджеста; её требует живой клиент с
// signature-type: rsa), а публичный ключ встраивается в
// index-meta.plist. У apk — третья форма той же RSA-подписи: подпись
// ИНДЕКСА живёт ВНУТРИ APKINDEX.tar.gz tar-членом
// `.SIGN.RSA.<keyid>` поверх CЖАТЫХ байт второго gzip-члена
// (RSA+SHA-1; apk-tools v2 package.c, v3 extract_v2.c — таблица типов
// «RSA» → SHA-1), а публичный ключ клиент кладёт в /etc/apk/keys под
// именем keyid. Реализация — mod/sign/rsasha256 (сессии 139, 195);
// инъекция в адаптеры — через RsaSignerInjector (xbps — RsaSignerInjector
// с сессии 139, apk — с сессии 195; как NarSignerInjector для nix).
// wire (cmd) type-assert'ит адаптер к RsaSignerInjector и внедряет;
// nil = репо не подписываются.

package port

import "context"

// RsaSigner — источник RSA-подписи xbps и apk. SignSHA256 принимает
// ровно 32-байтовый дайджест SHA-256 содержимого (нарушение длины —
// ошибка, не паника) и возвращает сырые байты подписи PKCS#1 v1.5 (512
// для ключа 4096) — формат .sig2 (verifysig.c xbps-rindex).
// SignSHA256SHA1DigestInfo принимает тот же дайджест, но оборачивает его
// в SHA-1-DigestInfo (OID 1.3.14.3.2.26) — формат легаси-подписи `.sig`,
// которую запрашивает живой клиент void при signature-type: rsa
// (проверено живой подписью Void: openssl pkeyutl -verifyrecover даёт
// DigestInfo SHA-1, последние 32 байта — sha256 пакета).
// SignSHA1DigestInfo принимает ровно 20-байтовый дайджест SHA-1 и
// возвращает PKCS#1 v1.5-подпись с SHA-1-DigestInfo — формат подписи
// ИНДЕКСА apk (`.SIGN.RSA.<keyid>` внутри APKINDEX.tar.gz; apk-tools
// проверяет её EVP_VerifyFinal с SHA-1, поэтому дайджест обязан быть
// sha1, а не sha256).
// PublicKeyPEM отдаёт публичный ключ в SPKI-PEM (`PUBLIC KEY`) для
// index-meta.plist и ручек раздачи (сессии 142, 195).
type RsaSigner interface {
	SignSHA256(ctx context.Context, digest []byte) ([]byte, error)
	SignSHA256SHA1DigestInfo(ctx context.Context, digest []byte) ([]byte, error)
	SignSHA1DigestInfo(ctx context.Context, digest []byte) ([]byte, error)
	PublicKeyPEM() ([]byte, error)
}

// RsaSignerInjector — опциональная способность RepoAdapter'а принять
// подписчик. wire type-assert'ит каждый собранный адаптер к этому
// интерфейсу и внедряет RsaSigner в поддерживающие (v1 — xbps:
// .sig2/.sig пакетов; apk: подпись индекса, сессия 195). Адаптеры без
// RSA-подписи не реализуют его — wire пропускает. Держим в port, т.к.
// это общий контракт генераторов, а не xbps-специфика (зеркально
// NarSignerInjector для nix).
type RsaSignerInjector interface {
	SetRsaSigner(s RsaSigner)
}
