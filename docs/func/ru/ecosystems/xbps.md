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

# xbps (Void Linux)

URL-префикс — `xbps`. Лэйаут Void плоский: в корне репозитория лежат
индекс `<arch>-repodata` и пакеты `<pkgver>.<arch>.xbps` с подписями
`.xbps.sig2` и `.xbps.sig`. Пакеты content-addressed по имени с версией —
immutable-кеш навсегда; `<arch>-repodata` ревалидируется коротким TTL.
Метаданные upstream отдаются побайтово — подписи `.sig2`/`.sig` валидны.

## Формат пакета

`.xbps` — tar-архив, сжатый целиком: zstd (дефолт `xbps-create` с 0.59),
gzip или raw tar. Внутри — `./props.plist` (поля пакета), `./files.plist`
и payload-файлы. Ar-контейнера (`!<arch>`) в `.xbps` не существует —
разбор ar не поддерживается; xz — честная ошибка
(`ErrUnsupportedCompression`), отдельная микросессия по образцу 103.
Читается ровно `./props.plist` (имя с каноническим префиксом `./`),
payload в память не поднимается; reindex личного репо строится на его
полях, декомпресс ограничен 1 GiB, тело `props.plist` — 1 MiB.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"void","ecosystem":"xbps","base_url":"https://repo-default.voidlinux.org/current","mode":"proxy","enabled":true}'
```

`mode = "mirror"` — фоновый sync; `include` — список архитектур
(например `["x86_64","aarch64"]`). Индекс каждой архитектуры —
`<arch>-repodata`; общего корневого индекса нет, поэтому пустой
`include` — ошибка (как у apk). `noarch`-пакеты входят в каждую
arch-группу и при нескольких архитектурах скачиваются один раз. Sync
забирает пакеты вместе с обеими подписями (`.sig2` и `.sig`) — раздача
зеркала полноценна для живого клиента.

## Кеш-прокси: /etc/xbps.d

```
# /etc/xbps.d/00-repository-main.conf
repository=http://<хражевник>:29202/xbps/void
```

Файл с тем же именем в `/etc/xbps.d` перекрывает системный из
`/usr/share/xbps.d` (xbps.d(5)) — единственный настроенный репозиторий
`void`, мимо прокси клиент не уйдёт. Если `include` remote'а ограничен,
индекс запрошенной архитектуры отсутствует upstream — запрос вернёт 404.

## Подпись

Каждый пакет подписан ДВУМЯ detached-подписями, как у upstream Void:

- `.xbps.sig2` — RSA-4096, PKCS#1 v1.5 поверх SHA-256 пакета (сырые байты
  тела; так её считает `xbps-rindex`), проверяется
  `openssl dgst -sha256 -verify`;
- `.xbps.sig` — та же RSA-подпись, но DigestInfo помечен OID SHA-1
  (`1.3.14.3.2.26`), а внутри лежит SHA-256-дайджест пакета
  (`openssl pkeyutl -verifyrecover` показывает `30 2d 30 09 06 05 2b 0e 03
  02 1a 05 00 04 20` + `sha256(пакет)`). Именно `.sig` запрашивает живой
  клиент при `signature-type: rsa`; фолбэка на `.sig2` он не делает —
  поэтому без `.sig` установка падает на 404. `openssl dgst -sha256 -verify`
  на `.sig` законно падает `bad signature` — это не ошибка формата.

Сам `repodata` не подписан (`<arch>-repodata.sig2` отсутствует):
публичный ключ (PEM-SPKI) встроен в запись `index-meta.plist` внутри
контейнера, клиент делает TOFU-импорт ключа с промптом. Обе подписи —
immutable-объекты: прокси и зеркало отдают их побайтово.

## Личное репо

Upload `.xbps` где угодно под корнем репо (имена —
`<pkgver>.<arch>.xbps`); `<arch>-repodata` генерируется, upload туда
запрещён. Reindex создаёт `<arch>-repodata` (zstd level 9 + pax-tar:
`index.plist`/`index-meta.plist`/`stage.plist`), `noarch`-пакеты входят
в каждую arch-группу, на каждый пакет эмитятся ОБЕ подписи — `.sig2` и
легаси `.sig` — ключом инстанса; публичный ключ встраивается в
`index-meta.plist` (base64-PEM). Пакет,
чья props-запись не совпадает с именем файла, роняет задачу reindex
честной ошибкой.

В `<arch>-repodata` попадает не более одной записи на `PkgName`: из
нескольких версий одного пакета в `index.plist` остаётся новейшая
(порядок версий — как у клиента, `xbps_cmpver`: ревизия `_N` сравнивается
после версии, `alpha`/`beta`/`pre`/`rc`/`pl` — модификаторы, `~` —
пропускаемый байт), прочие остаются в storage и защищаются
retention/пинами — так же ведёт себя upstream `xbps-rindex`. Иначе
клиент (proplib) молча оставляет последнюю запись словаря с этим ключом,
и какая версия победит, решает лексический порядок ключей storage, а не
порядок версий. Клиент:

```sh
# TOFU-импорт ключа: xbps-install при первом обращении спросит
# fingerprint — сверьте его с PEM из xbps-key до подтверждения.
curl -s http://<хражевник>:29202/repo/<name>/xbps-key
echo 'repository=http://<хражевник>:29202/repo/<name>' \
  > /etc/xbps.d/00-repository-main.conf
xbps-install -S <пакет>
```

Публичный ключ инстанса отдаётся `GET /repo/<name>/xbps-key` (PEM) —
точка сверки fingerprint при TOFU-импорте; без живого подписчика
маршрут не регистрируется (404). Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream              | Класс    | TTL      |
|----------------------------|----------|----------|
| `*.xbps`                   | immutable| навсегда |
| `*.xbps.sig2`, `*.sig`     | immutable| навсегда |
| `*-repodata` (в корне)     | mutable  | 5m       |
| прочее                     | mutable  | 1m       |
