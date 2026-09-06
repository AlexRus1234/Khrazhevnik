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

# Чеклист релиза

Ручные проверки реальными пакетными менеджерами перед публикацией
релиза. В CI это невозможно: nested-podman на раннере не поддерживается
(rootless runner не даёт mount `/proc` внутри контейнера-клиента), а
фаззинг/интеграция покрывают формат, но не поведение живых клиентов.
Поэтому: CI (unit/integration/binary-smoke) + локальный container-smoke
+ этот ручной чеклист.

База: [docs/func/ru/personal-repos.md](func/ru/personal-repos.md) —
как создать репо, загрузить пакет, запустить reindex. Подразумевается
стенд: собранный контейнер `make image` + `podman run` (см.
[func/ru/deploy.md](func/ru/deploy.md)).

## Заметки совместимости

- **Прокси-кеш регистрочувствителен (сессия 19):** apt-ключи хранения
  больше не лоуэркейсятся (`/pool/Foo.deb` ≠ `/pool/foo.deb`). При
  обновлении с прежних версий объекты, закешированные под
  lowercase-ключами, промахнутся один раз и перекачаются — объём
  разовый, на корректность не влияет. В RELEASE-заметки релиза
  включить тот же пункт.
- **Прокси-кеш больше не расживает gzip:** outbound-клиент отключил
  прозрачное сжатие; клиенты получают ровно байты upstream с его
  Content-Encoding. Проверить на стенде `curl --raw`-сравнением
  с прямым скачиванием.

## 0. Автоматизация перед ручными проверками

- [ ] CI на коммите-кандидате зелёный (build-test: vet → gofmt →
      golangci-lint → test [+race] → integration → binary-smoke).
- [ ] CI distro-test (workflow_dispatch, `run_distro_tests=true`):
      5/5 ног зелёные — покрывает §1 (кеш-прокси, каждая экосистема)
      в автоматике; ручная проверка §1 остаётся для версий клиентов,
      отличных от контейнерных.
- [ ] Локально: `make image && make smoke` — контейнер поднимается,
      `/healthz` → `ok`, bootstrap, прокси byte-exact, SIGTERM — exit 0.
- [ ] Bootstrap через UI (`/ui/`) и через `POST /api/v1/setup`.

## 1. Кеш-прокси (каждая экосистема)

Настройка клиентов — [func/ru/ecosystems/](func/ru/ecosystems/).

- [ ] apt: `apt-get update` через `/<хражевник>:29202/apt/<remote>`;
      повторный `apt-get install` — `X-Cache: HIT` на пакете; подписи
      upstream валидны (никаких `trusted=yes`).
- [ ] dnf: `dnf makecache` + `dnf install` через `rpm/<remote>`;
      `gpgcheck=1` без импорта новых ключей.
- [ ] zypper: `zypper refresh` + `zypper install` через `rpm/<remote>`.
- [ ] pacman: `pacman -Sy` + `pacman -S` через `pacman/<remote>`
      (`Server = …/<remote>/$repo/os/$arch`).
- [ ] apk: `apk update` + `apk add` через `apk/<remote>`.
- [ ] nix: `nix-shell -p hello --substituters http://<хражевник>:29202/nix/<remote>`;
      nar — `X-Cache: HIT` со второго раза; `trusted-public-keys`
      остался от upstream.

## 2. Личные репо (каждая экосистема, подпись)

Создать репо, upload своего пакета, reindex (флоу —
[personal-repos.md](func/ru/personal-repos.md)). Install реальным PM
**с валидацией подписи ключом инстанса**:

- [ ] apt: `apt-get update && apt-get install` из личного репо с
      `signed-by=key.asc` (без `trusted=yes`); ключ —
      `GET /repo/<name>/key.asc`.
- [ ] dnf: `dnf makecache && dnf install` из личного репо с
      `gpgcheck=1` + `rpm --import key.asc`.
- [ ] zypper: `zypper refresh && zypper install` из личного репо
      (тот же формат репо; ключ через `rpm --import`).
- [ ] pacman: `pacman -Sy && pacman -S` из личного репо с
      `pacman-key --add key.asc`; `SigLevel = Required DatabaseOptional`.
- [ ] apk: `apk update && apk add` из личного репо с ключом в
      `/etc/apk/keys/`.
- [ ] nix: `nix-shell -p <pkg>` с `--substituters http://<хражевник>:29202/repo/<name>`
      и `trusted-public-keys = khrazhevnik:<pubkey>` (переподписанные
      narinfo валидируются ключом инстанса; `<pubkey>` —
      `GET /repo/<name>/nix-key.asc`).

## 3. Негативные проверки

- [ ] Upload сверх `publish.max_object_size` → 413 `too_large`, файл
      не появился.
- [ ] Upload сверх квоты репо → 413 `quota_exceeded`.
- [ ] Перезапись существующего ключа без `force` → 409 `conflict`.
- [ ] Upload в генерируемые пути (`dists/*`, `repodata/*`,
      `APKINDEX.tar.gz`, `*.db`) → 400.
- [ ] Повреждённый пакет (обрезанный `.deb`) → reindex-задача
      завершается ошибкой, честный `error` в `/api/v1/tasks/{id}`.

## 4. Публикация

- [ ] Тег `vX.Y.Z` на коммите после всех правок.
- [ ] Workflow с `push_to_registry=true`, `publish_github=true`,
      `publish_codeberg=true` (секреты `UPLOAD_TOKEN`/`TOKEN_GITHUB`/
      `TOKEN_CODEBERG` настроены) — зелёный; артефакт
      `khrazhevnik-vX.Y.Z-linux-amd64` и образ
      `git.yadr00.internal/build/khrazhevnik:vX.Y.Z` + `:latest`
      опубликованы.
- [ ] Release notes: сводка функций (кеш-прокси / зеркало / личные
      репо), 5 экосистем, матрица storage (fs/s3) × БД
      (sqlite/postgres/mariadb), ссылка на [func/ru/](func/ru/).
