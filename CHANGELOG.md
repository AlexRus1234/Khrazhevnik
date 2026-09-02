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

Закрытие находок аудита 2026-08-27 (сессии 19–26, этап M4) и
пост-верификационный ремонт (сессии 27–31, M4-Р). Релизная
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
- **Upload-стриминг (сессия 27):** read-deadline в стриминге upload —
  WriteTimeout админского слушателя не рвёт большие (1GiB) тела.
- **Зеркало (сессия 28):** отменённый sync фиксируется как failed
  («interrupted by cancel») с сохранением прогресса, а не succeeded;
  чистка deaths-map планировщика.
- **Retention by-hash (сессия 29):** by-hash-объекты живут два
  поколения Release (marker `.retained`) — GC не удаляет индексы
  актуального Release.
- **Logout (сессия 30):** сбой каталога БД при отзыве сессии — 503
  вместо 500.
- **Док-хвосты (сессия 31):** постамбула сессии 21 (VALUES-col),
  комментарии, config.md.

## Постаудит 2 (unreleased)

Ремонт второй волны аудита 2026-08-30 (сессии 32–46, этап M4-Р2).

- **Stall-дедлайны (сессия 32):** recorder-обёртки ответов реализуют
  `Unwrap() http.ResponseWriter` — таймауты слушателя видят реальный
  writer и срабатывают на зависших клиентах.
- **nix fingerprint (сессия 33):** narinfo переподписывается
  fingerprint'ом PathInfo («1;StorePath;NarHash;NarSize;Refs»), а не
  байтами файла; классификация путей — nix-base32 (32/52), не hex.
- **Капы парсеров (сессия 34):** лимит счётчика пакетов rpm-md
  primary.xml, лимит длины строки apt stanza, капы gzip-декомпрессии —
  OOM-guard на враждебных индексах.
- **Shutdown (сессия 35):** фаза фоновых задач выполняется независимо
  от исхода HTTP-фазы; ошибки стадий джойнятся, а не затираются.
- **Публичный порт (сессия 36):** `X-Content-Type-Options: nosniff` и
  явные Content-Type на раздаче (stored-XSS).
- **Аудит (сессия 37):** записи аудита переживают обрыв соединения
  клиентом (WithoutCancel); покрывают 401/403, паники, logout и setup.
- **Зеркало (сессия 38):** дедупликация планового и ручного sync по
  remote — параллельные задачи одного upstream не плодятся.
- **postgres (сессия 39):** гонка создания первого пользователя под
  READ COMMITTED.
- **Ключи подписи (сессия 40):** keygen с O_EXCL (без перезаписи
  существующих), атомарная запись файлов ключей, валидация
  приватности; битый ключевой материал — `domain.KeyMaterialError`,
  старт падает (не тихая деградация).
- **Гранты (сессия 41):** выдача права записи различает FK-нарушение
  (404) и идемпотентный дубль (204).
- **Конфиг (сессия 42, BREAKING):** удалён мёртвый `cache.mutable_ttl`
  (определялся и валидировался, но не потреблялся; TTL mutable-индексов
  — константы адаптеров) — strict TOML теперь отвергает его в старых
  конфигах с именем ключа; `mirror.max_bandwidth` и
  `publish.default_quota_bytes` меньше нуля роняют старт вместо
  молчаливого «unlimited»; опечатка `KHRZ_LOG_LEVEL` видна — warning
  со значением и подсказкой уровней, уровень остаётся info.
- **Метрики (сессия 43):** гистограммы заполняются через `Observe`
  (а не инкрементами counter'ов) + runtime-коллекторы Go.
- **Storage durability (сессия 44):** чистка multipart-сирот S3
  (sweep незавершённых upload'ов); fs — tmp-утечки при ошибках
  Commit/Abort.
- **Web (сессия 45):** честный 503 прокси при сбоях хранения, revoke
  api-токена по `{id}`, валидация TTL токенов, проверка экосистемы
  при создании/изменении репо.
- **Доки (сессия 46):** синхронизация документации с реальностью
  после волны 32–45.
