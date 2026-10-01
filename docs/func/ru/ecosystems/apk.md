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

# apk (Alpine Linux)

URL-префикс — `apk`. Пакеты content-addressed по имени+версии —
immutable-кеш навсегда; `APKINDEX.tar.gz` ревалидируется коротким TTL.
Метаданные upstream отдаются побайтово — подписи upstream валидны.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"alpine","ecosystem":"apk","base_url":"https://dl-cdn.alpinelinux.org/alpine","mode":"proxy","enabled":true}'
```

`mode = "mirror"` — фоновый sync; `include` — список архитектур
(например `["x86_64","aarch64"]`), пустой `include` — ошибка (у apk
нет корневого индекса архитектур).

## Кеш-прокси: /etc/apk/repositories

```
http://<хражевник>:29202/apk/alpine/v3.21/main
http://<хражевник>:29202/apk/alpine/v3.21/community
```

## Личное репо

Пакет кладётся в каталог своей архитектуры: `<архитектура>/<файл>.apk`
(`arch` из `.PKGINFO`); пакет `arch = noarch` — в каталог `noarch/`. Иные
пути (в том числе корень репо) — `400 validation_error`. Reindex пишет по
индексу на архитектуру — `<архитектура>/APKINDEX.tar.gz` (gzip+tar с
файлом `APKINDEX` в формате «K:V»; поле `F:` — фактический путь пакета от
корня репо). `noarch`-записи входят в индекс КАЖДОЙ архитектуры (клиент
читает индекс только своей и файл тянет из `/noarch/`). Индекс в корне
репо не генерируется (ранее записанный не удаляется — чистится руками).

Индекс подписывается ключом инстанса ВНУТРИ файла — ровно как у Alpine:
первым gzip-членом идёт tar с единственным членом
`.SIGN.RSA.khrazhevnik.rsa.pub` (сырые байты подписи RSA PKCS#1 v1.5
над SHA-1-DigestInfo от sha1 СЖАТЫХ байт второго, телесного члена
`APKINDEX.tar.gz`), второй член — сам индекс. Архив при этом ОДИН и
непрерывный через границу членов (концевые нулевые блоки tar — только в
теле), поэтому и наш парсер, и apk видят оба члена. Отдельного
`APKINDEX.tar.gz.sig` больше нет: apk его не запрашивает — на CDN Alpine
он тоже отдаёт 404, подпись там всегда лежит первым членом внутри
`APKINDEX.tar.gz`. Формат сверен побайтово эталоном Alpine
(`openssl pkeyutl -verifyrecover` по члену `.SIGN.RSA.…` индекса
edge/main/x86_64: DigestInfo = OID `sha1`
(`3021300906052b0e03021a05000414`) + 20 байт дайджеста; дайджест совпал с
sha1 СЖАТОГО хвоста от границы первого члена и НЕ совпал с sha1
разжатого tar). `--allow-untrusted` не нужен: клиент проверяет подпись и
ставит пакет как обычно (живая проба 195 — alpine:3.21 apk-tools 2.14.6 и
alpine:edge 3.0.7, `apk update`/`apk add`/`apk fetch` — exit 0 без флага).

Ключ клиенту — `GET /repo/<name>/apk-key` (SPKI-PEM, тот же ключ инстанса,
что и `xbps-key`). Имя файла в `/etc/apk/keys/` обязано совпадать с
`<keyid>` из имени tar-члена (`.SIGN.<алгоритм>.<keyid>` — apk считает
keyid именно именем файла): у нас это `khrazhevnik.rsa.pub`. Ошибка в
формате или имени файла не диагностируется иначе, чем ровно
`WARNING: updating and opening <repo>: UNTRUSTED signature`. Клиент (живая
проба 195):

```sh
curl -sO http://<хражевник>:29202/repo/<name>/apk-key
cp apk-key /etc/apk/keys/khrazhevnik.rsa.pub   # имя = keyid из .SIGN.RSA.<keyid>
echo 'http://<хражевник>:29202/repo/<name>' >> /etc/apk/repositories
apk update                            # exit 0
apk add <пакет>                       # exit 0 — пакет ставится и запускается
```

Архитектуру в строке `/etc/apk/repositories` указывать не нужно — клиент
подставляет свою сам и запрашивает `<repo-url>/<арх>/APKINDEX.tar.gz`.
Граница: правило верно для индексов, которые пишет reindex; апстримные
индексы кеш-прокси отдаёт побайтово со своими подписями. Поле `C:` записи — `Q1` + base64 от sha1 СЖАТЫХ байт control-секции `.apk`
(gzip-члена с `./.PKGINFO`), ровно как считает apk-tools: генерировать
иначе нельзя — клиент отвергает пакет на сверке (`BAD signature` в 2.x /
`v2 package integrity error` в 3.x). Инвариант проверен живьём на реальном
пакете Alpine (`tree-2.2.1-r0` из v3.21: `C:` совпал с апстримным
APKINDEX) и установкой `apk add` в alpine:3.21 и alpine:edge. `S:` —
размер всего файла. Граница: правило проверено на gzip-пакетах v2; для
`.apk` v3 (zstd/raw tar) генератор по-прежнему пишет sha1 ВСЕГО файла —
семантика `C:` у apk-tools 3.x для такой раскладки не проверена (находка
сессии 193, отдельная микросессия).

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                        | Класс    | TTL      |
|--------------------------------------|----------|----------|
| `*.apk`                              | immutable| навсегда |
| `APKINDEX.tar.gz`, `APKINDEX.json`     | mutable | 5m |
| `keys/*` (публичные ключи)           | mutable  | 1h       |
| прочее                               | mutable  | 1m       |
