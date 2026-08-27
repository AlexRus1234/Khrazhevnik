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

# Дорожная карта

## M1 — рабочий кеш-прокси apt + dnf в контейнере ✅ v0.1.0

**Статус: завершён (2026-08-23, тег v0.1.0).**

- Контракты `port/*` и модели `domain`, тестовые примитивы.
- TOML-конфиг, compile-time реестр модулей, wire, graceful shutdown, `/healthz`.
- Хранилище fs + каталог sqlite, goose-миграции.
- Аутентификация: пользователи, scoped-токены, middleware.
- Движок кеша: pull-through, singleflight, immutable/mutable.
- Адаптеры apt и rpm-md (dnf + zypper), фаззинг парсеров.
- Админ-API, реестр задач, метрики, аудит.
- Containerfile, quadlet, smoke-тесты в CI.

### Релиз v0.1.0

Первый рабочий релиз: прозрачный pull-through кеш-прокси apt и rpm-md
(dnf + zypper) в OCI-контейнере из scratch.

Что умеет:
- Кеш-прокси apt и rpm-md: метаданные upstream отдаются побайтово
  (подписи/чексуммы валидны), immutable-пакеты кешируются, mutable-
  индексы ревалидируются по ETag/Last-Modified, stale-if-error,
  отрицательное кеширование 404/5xx, singleflight против stampede.
- Админ-API (REST, порт :30202): bootstrap `/setup`, JWT-сессии,
  scoped API-токены, CRUD remotes, снимки фоновых задач, статистика
  кеша, аудит с keyset-пагинацией; роль/token_version сверяются с БД
  на каждом запросе, bcrypt с guard, constant-time, rate-limit /login.
- Метрики Prometheus (`/metrics` за auth).
- Конфиг: defaults → TOML → env (`KHRZ_*`, `file://`-секреты для
  quadlet); sqlite (modernc, CGO-free) + fs-хранилище по умолчанию.
- Контейнер: scratch, non-root UID 65534, read-only rootfs, PID 1 =
  бинарник, graceful shutdown каскадом (HTTP 5с + задачи 30с).
  Rootless podman quadlet + AutoUpdate=registry.
- CI: vet → lint → test (+race) → integration → сборка; отдельная
  job собирает OCI-образ и гоняет дымовой E2E (healthz, bootstrap,
  byte-exact прокси, 404, SIGTERM-shutdown); push в registry на тег.

## M2 — зеркало и все экосистемы ✅

**Статус: завершён (сессии 11–13, 17).**

- Sync-воркеры зеркал с resume, планировщик (сессия 11 — выполнена).
- Адаптеры pacman (.tar.zst) и apk (APKINDEX).
- Адаптер nix (narinfo/nar.xz прокси).
- S3-storage, драйверы postgres/mariadb, контейнерные тесты в CI.

## M3 — личные подписанные репозитории + UI ✅ (релиз v1.0.0 отложен)

**Статус: завершён функционально (сессии 14–16, 18.1–18.4)** — код,
UI, документация. Тег v1.0.0 и публикация артефактов — после
проверочного рефакторинга (чеклист — [RELEASE.md](RELEASE.md)).

- Publish-ядро: upload, квоты, RBAC, генерация apt-индексов.
- OpenPGP-подпись личных репо (+ переподпись nix-narinfo).
- Генераторы метаданных rpm-md/pacman/apk/nix.
- Vue 3 SPA (`//go:embed`, i18n ru/en), Playwright e2e-смоук (opt-in).
- Пользовательская документация (`docs/func/ru/`: quickstart, config,
  api, ui, ecosystems/, deploy, personal-repos) + README + RELEASE.md.
