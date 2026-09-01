<!--
Хражевник — кеш-прокси и зеркало linux-репозиториев
Copyright (C) 2026 AlexRus1234

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
-->

# Changelog

## Постаудит (unreleased)

Закрытие находок аудита 2026-08-27 (сессии 19–26, этап M4). Релизная
приёмка — отдельно, по чеклисту [RELEASE.md](docs/RELEASE.md).

- **Кеш-прокси (сессия 19):** регистрочувствительные ключи хранения;
  outbound-клиент без прозрачного gzip (byte-exact прокси); честные
  ответы при checksum-mismatch upstream.
- **Storage (сессия 20):** ошибка листинга ≠ пустой результат —
  fail-closed для зеркал и reindex; List-генераторы единым контрактом.
- **Каталог БД (сессия 21):** паритет драйверов sqlite/postgres/mariadb
  контрактными suite: no-op UPDATE на mariadb, revoke roundtrip,
  FK-удаления, граница ключа 767 байт, пустая страница аудита.
- **HTTP-безопасность (сессия 22):** `http.trusted_proxies` (XFF для
  rate-limit логина за reverse-proxy); минимум длины JWT-секрета
  32 байта с проверкой на старте.
- **Зеркало (сессия 23):** планировщик per-remote с случайным jitter;
  отказ upstream не блокирует остальные remotes.
- **Publish (сессия 24):** fail-closed генерация индексов (порченый
  пакет не затирает прошлые метаданные); by-hash GC; инварианты квот.
- **Auth и задачи (сессия 25):** сбой БД — 5xx, а не маскировка под
  403; персистентные revocation JWT-сессий (переживают рестарт);
  конфигурируемый bcrypt cost; тайминг-паритет логина; panic recovery
  и bounded история фоновых задач.
- **Полировка (сессия 26):** strict TOML — неизвестный ключ роняет
  старт с именем поля и строкой; cap limit аудита ≤ 1000; покрытие
  в CI считается по merged-профилю unit + integration; честные ошибки
  неподдерживаемых форматов индексов (apt `Packages.xz`, pacman
  `.db.tar.gz`, rpm-md `.zck`/`.zst`/`.xz`/`.bz2`) вместо generic
  failed.
- **Конфиг (сессия 42, BREAKING):** удалён мёртвый `cache.mutable_ttl`
  (определялся и валидировался, но не потреблялся; TTL mutable-индексов
  — константы адаптеров) — strict TOML теперь отвергает его в старых
  конфигах с именем ключа; `mirror.max_bandwidth` и
  `publish.default_quota_bytes` меньше нуля роняют старт вместо
  молчаливого «unlimited»; опечатка `KHRZ_LOG_LEVEL` видна — warning
  со значением и подсказкой уровней, уровень остаётся info.
