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

# rpm-md (dnf / Zypper: Fedora, RHEL, openSUSE)

Один адаптер для dnf и Zypper — формат repomd общий. URL-префикс —
`rpm` (короче имени адаптера `rpm-md`, как пишут в `.repo` baseurl).
Метаданные upstream отдаются побайтово — GPG-подписи `repomd.xml.asc`
валидны, keyring клиента не меняется.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"fedora","ecosystem":"rpm-md","base_url":"https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Everything/x86_64/os/","mode":"proxy","enabled":true}'
```

`mode = "mirror"` — фоновый sync (репо — единое целое по repomd);
`include` для rpm-md не используется.

## Кеш-прокси: .repo

`/etc/yum.repos.d/khrazhevnik.repo` (dnf) или
`/etc/zypp/repos.d/khrazhevnik.repo` (Zypper):

```ini
[khrazhevnik-fedora]
name=khrazhevnik proxy of Fedora
baseurl=http://<хражевник>:29202/rpm/fedora/releases/$releasever/Everything/$basearch/os/
enabled=1
gpgcheck=1
```

`gpgcheck=1` работает без изменений: подписи upstream сохранены.

## Личное репо

Upload `.rpm/.drpm/.src.rpm` где угодно под корнем репо, КРОМЕ
`repodata/` (генерируется — 400). Reindex создаёт
`repodata/primary.xml.gz` и `repodata/repomd.xml` + detached-подпись
`repodata/repomd.xml.asc` ключом инстанса. Клиент:

```sh
curl -sO http://<хражевник>:29202/repo/<name>/key.asc
rpm --import key.asc
cat > /etc/yum.repos.d/<name>.repo << 'EOF'
[<name>]
name=<name> personal repo
baseurl=http://<хражевник>:29202/repo/<name>
enabled=1
gpgcheck=1
EOF
dnf makecache && dnf install <пакет>
```

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                          | Класс    | TTL      |
|----------------------------------------|----------|----------|
| `*.rpm`, `*.drpm`, `*.src.rpm`         | immutable| навсегда |
| `repodata/repomd.xml` (+`.asc`,`.key`) | mutable  | 5m       |
| repodata с хешем в имени (`<sha>-primary.xml.gz`) | immutable | навсегда |
| прочие repodata (primary/filelists/other, `*.sqlite.bz2`, zck) | mutable | 5m |
| прочее (`media.1/*`)                   | mutable  | 1m       |
