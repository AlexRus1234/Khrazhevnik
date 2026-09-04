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

# Безопасность

Краткая модель угроз (постаудит, сессии 19–26; жёсткость
HTTPS/аудит — волны 19–63). Разбор конкретных
механизмов — [docs/func/ru/](docs/func/ru/); сообщения об уязвимостях —
через контакты владельца репозитория (не через публичный issue).

## Поверхность

| Слушатель | Порт (дефолт) | Доступ | Что открыто |
|---|---|---|---|
| публичный | :29202 | все | раздача пакетов `/<eco>/<remote>/…`, личные репо `/repo/<name>/…`, `/healthz` |
| админский | :30202 | все интерфейсы (дефолт; warn при старте) | REST `/api/v1`, метрики `/metrics`, SPA `/ui` |

Публичный слушатель не содержит ни одной мутирующей операции без auth,
кроме upload в личные репо по scoped-токену (`repo:<id>:write`).
Дефолт `:30202` слушает все интерфейсы — старт пишет warning;
привязка к loopback — ответственность деплоя (quadlet:
`PublishPort=127.0.0.1:30202:30202`), публикация наружу — осознанное
решение администратора (reverse-proxy с TLS).

## Границы доверия

- **Reverse-proxy / XFF:** заголовок `X-Forwarded-For` по умолчанию
  игнорируется (подделываемый). Доверенные границы задаются явным
  списком `http.trusted_proxies` (CIDR); клиент за доверенным прокси
  попадает в rate-limit корзину по своему IP, а не по адресу прокси.
- **Upstream репозитории:** метаданные отдаются клиенту побайтово —
  валидация подписей/чексумм остаётся на клиенте и его keyring.
  Чексуммы при зеркалировании сверяются с корневым индексом upstream;
  mismatch — честная ошибка, объект не отдаётся.
- **Клиентские пути:** единая точка path-traversal для всех путей из
  запросов (`domain`-валидация, без прямого обращения к диску).

## Аутентификация и сессии

- Пароли — bcrypt; стоимость конфигурируется (`auth.bcrypt_cost`,
  диапазон 4–15, дефолт 12), логин — с тайминг-паритетом (несуществующий
  пользователь проверяется по dummy-hash, тайминг-оракул перечисления
  закрыт).
- JWT-сессии админки: секрет ≥ 32 байт (проверка на старте), logout —
  **персистентная** revocation в БД (переживает рестарт процесса), роль
  и `token_version` сверяются на каждом запросе.
- API-токены: хранится только sha256, скоупы (`admin`,
  `repo:<id>:write`) минимально достаточные, отзыв сохраняет запись для
  аудита. Scope `admin` требует текущую admin-роль владельца: смена
  роли гасит admin-токены немедленно, repo-токены — нет.
- Rate-limit логина: 10/мин на клиента (с учётом trusted_proxies);
  сбой БД — 5xx, не маскировка под 403.

## Отказ в обслуживании и целостность

- Пул фоновых задач: panic recovery на задаче (паника не кладёт
  процесс), bounded история, graceful shutdown каскадом.
- Квоты личных репо (max_bytes/max_objects) и лимит одного объекта;
  перезапись существующего ключа — 409 (`force` — только админ, с аудитом).
- Стриминг-парсеры метаданных с декомпресс-лимитами (защита от
  zip-bomb), фаззинг с первого адаптера.
- Аудит всех мутаций (actor/action/object/result/detail); limit
  страницы аудита капится сервером (≤ 1000).

## Контейнер

OCI из `scratch`: бинарник + CA-bundle, `USER 65534:65534`, read-only
rootfs, writable — только volume `/var/lib/khrazhevnik`; секреты —
podman secrets / `file://`-развёртка env (не в args и не в образе).
