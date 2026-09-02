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

# Личные репозитории

Личное репо пользователя — `POST /api/v1/repos` (админ), затем upload
пакетов через `PUT /api/v1/repos/{id}/objects/<path>` (владелец или
scoped-токен `repo:<id>:write`) и `POST /api/v1/repos/{id}/reindex`
(фоновая задача генерации индексов). Чтение публичное: `GET /repo/<name>/*`
на порту :29202.

Поддерживаемые экосистемы v1: apt, rpm-md, pacman, apk, nix. Каждая имеет
свой генератор индексов (`mod/ecosystem/*/gen.go`, сессии 14/16) и
опциональную подпись метаданных ключом инстанса (сессия 15/16).
Настройка клиентов по экосистемам — в [ecosystems/](ecosystems/);
эта страница — общий flow публикации. Управлять репо можно и из
[веб-админки](ui.md).

## Общий flow

```sh
# 1. Админ: создать репо (name — slug в URL, ecosystem — имя адаптера).
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}' | jq -r .token)
curl -s -X POST http://127.0.0.1:30202/api/v1/repos \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"alice","owner_id":2,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0}}'

# 2. Владелец: scoped-токен repo:<id>:write (или сессия владельца).
REPOWRITE=$(curl -s -X POST http://127.0.0.1:30202/api/v1/users/2/api-tokens \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"repo-write","scopes":["repo:1:write"]}' | jq -r .token)

# 3. Upload пакетов (Content-Length обязателен — v1 стримит с сверкой).
curl -s -X PUT "http://127.0.0.1:30202/api/v1/repos/1/objects/pool/main/f/foo/foo_1.0-1_amd64.deb" \
  -H "Authorization: Bearer $REPOWRITE" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @foo_1.0-1_amd64.deb

# 4. Reindex → 202 (фонова задача). Проверка статуса — /api/v1/tasks/{id}.
curl -s -X POST http://127.0.0.1:30202/api/v1/repos/1/reindex \
  -H "Authorization: Bearer $REPOWRITE"
```

После reindex индексы доступны публично: `GET /repo/alice/<путь-индекса>`.

**Конвенция ключей (v1):** upload и delete лоуэркейсят путь —
опубликованные объекты хранятся в нижнем регистре (`/pool/Foo.deb`
при upload станет `pool/foo.deb`); публичный GET (`/repo/<name>/*`)
нормализует запрос так же, поэтому apt-клиенты, запрашивающие индексы
с заглавной (`Packages`, `Release`), получают их без настроек.
(Прокси-кеш upstream-объектов — другое дело: там регистр путей
case-чувствителен и сохраняется, `cache/apt/<id>/pool/Foo.deb` и
`.../pool/foo.deb` — разные объекты.)

## apt

- **Upload:** `pool/...` с расширениями `.deb/.udeb/.ddeb/.dsc/.orig.tar.*/.debian.tar.*`.
  `dists/*` — генерируется, upload туда запрещён (400).
- **Индексы (reindex):** `dists/stable/main/binary-amd64/Packages` (+.gz +
  by-hash) + `dists/stable/Release` (Date/Suite/Components/Architectures/
  SHA256). Подпись: `InRelease` (cleartext) + `Release.gpg` (detached) —
  ключом инстанса OpenPGP (ed25519).
- **Клиент:** `deb [signed-by=/path/to/key.asc] http://<хражевник>:29202/repo/alice stable main`,
  где `key.asc` = `GET /repo/alice/key.asc`.
- **Публичный ключ:** `GET /repo/<name>/key.asc` (armored OpenPGP).
- **By-hash retention:** копии индексов `by-hash/sha256/<hash>` живут
  два поколения Release (текущее + предыдущее): клиент, скачавший
  Release до reindex, докачивает по старым хешам без 404. Поколения
  старее двух удаляются при reindex; хранить глубже — по усмотрению
  оператора (ручная чистка ключей `dists/…/by-hash/sha256/*`).

## rpm-md (dnf / Zypper)

- **Upload:** `.rpm/.drpm/.src.rpm` где угодно под корнем репо, КРОМЕ
  `repodata/` (генерируется, upload туда запрещён — 400).
- **Индексы (reindex):** `repodata/primary.xml.gz` (name/arch/version/
  checksum/location/time/size) + `repodata/repomd.xml` (checksum/open-
  checksum/size/timestamp). Подпись: `repodata/repomd.xml.asc` (detached,
  ключом инстанса OpenPGP).
- **Клиент:** `/etc/yum.repos.d/alice.repo`:
  ```ini
  [alice]
  name=alice personal repo
  baseurl=http://<хражевник>:29202/repo/alice
  enabled=1
  gpgcheck=1
  ```
  Ключ `GET /repo/alice/key.asc` импортируется через `rpm --import`.
- **Публичный ключ:** `GET /repo/<name>/key.asc` (armored OpenPGP).

## pacman (Arch)

- **Upload:** `.pkg.tar.zst` где угодно под корнем репо; `.db`,
  `.files`, `.sig` — генерируются, upload туда запрещён. Legacy
  `.pkg.tar.xz`/`.gz` не принимаются (400): нет xz/gz-декодера в
  whitelist зависимостей — переупакуйте в zst.
- **Индексы (reindex):** `<repo.Name>.db` (tar.zst с
  `<name>-<ver>-<arch>/desc`-записями) + `<repo.Name>.db.sig` (detached,
  ключом инстанса OpenPGP).
- **Клиент:** `/etc/pacman.conf`:
  ```ini
  [alice]
  SigLevel = Required DatabaseOptional
  Server = http://<хражевник>:29202/repo/alice
  ```
  Ключ `GET /repo/alice/key.asc` импортируется через `pacman-key --add`.
- **Публичный ключ:** `GET /repo/<name>/key.asc` (armored OpenPGP).

## apk (Alpine)

- **Upload:** `.apk` где угодно под корнем репо; `APKINDEX.tar.gz` —
  генерируется, upload туда запрещён.
- **Индексы (reindex):** `APKINDEX.tar.gz` (gzip+tar с файлом `APKINDEX`
  в формате «K:V» — C/P/V/A/F/...) + `APKINDEX.tar.gz.sig` (detached,
  ключом инстанса OpenPGP).
- **Клиент:** `/etc/apk/repositories`:
  ```
  http://<хражевник>:29202/repo/alice
  ```
  Ключ `GET /repo/alice/key.asc` копируется в `/etc/apk/keys/`.
- **Публичный ключ:** `GET /repo/<name>/key.asc` (armored OpenPGP).

## nix (binary cache)

- **Upload:** `<32 nix-base32>.narinfo` (в корне репо; хеш store path) +
  `nar/<52 nix-base32 fileHash>.nar.xz|.nar` (sha256 сжатого файла,
  (256−1)/5+1 = 52 символа — сессия 47). Прочие пути — 400. Алфавит
  nix-base32 — канонический nix (`[0-9a-z]` без `e`/`o`/`t`/`u`; hex
  с `e` ими не является).
- **Индексы (reindex):** narinfo **переподписываются** Sig ключом инстанса
  (ed25519, формат «name:signature» — 2 поля: имя ключа и base64-подпись
  fingerprint'а PathInfo). Это единственное место в проекте, где мы
  МЕНЯЕМ чужой файл: только поле Sig заменяется, остальное
  байт-точно (golden-тест на дифф). nar-файлы immutable, не трогаются.
- **Клиент:** `/etc/nix/nix.conf`:
  ```
  substituters = http://<хражевник>:29202/repo/alice https://cache.nixos.org
  trusted-public-keys = khrazhevnik:<pubkey-b64> cache.nixos.org-1:6NCHbD9f...
  ```
  `<pubkey-b64>` = `GET /repo/alice/nix-key.asc` (одна строка
  `khrazhevnik:<base64>`).
- **Публичный narinfo-ключ:** `GET /repo/<name>/nix-key.asc` (формат
  `name:pubkey-b64`, НЕ armored OpenPGP — у nix своя модель подписи).
- **Без NarSigner** (деградированный режим): narinfo отдаются как есть
  (подписи upstream валидны, если клиент им доверяет — см.
  [ecosystems/nix.md](ecosystems/nix.md)). Деградация — только для
  мягких ошибок инициализации (модуль не слинкован, keygen-сбой на
  пустом `signing.keys_dir`); битый ключевой материал
  (`domain.KeyMaterialError`) фатален — старт падает (сессия 40).

## Ручной чеклист релиза

Перед релизом v1.0.0 личные репо всех 5 экосистем проверяются руками
реальными пакетными менеджерами (apt/dnf/zypper/pacman/apk/nix):
install пакета из подписанного репо с валидацией подписи. Полный
чеклист — [docs/RELEASE.md](../../RELEASE.md). CI гоняет только формат
парсерами (свои же парсеры проверяют свои генераторы — roundtrip);
реальные клиенты — ручной чеклист (в CI невозможно: nested-podman).
