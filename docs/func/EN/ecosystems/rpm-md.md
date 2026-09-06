<!--
Hrazhevnik — caching proxy and mirror for Linux package repositories
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

One adapter for both dnf and Zypper — the repomd format is shared. The
URL prefix is `rpm` (shorter than the adapter name `rpm-md`, as written
in the `.repo` baseurl). Upstream metadata is served byte-for-byte —
`repomd.xml.asc` GPG signatures are valid, and the client keyring does
not change.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"fedora","ecosystem":"rpm-md","base_url":"https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Everything/x86_64/os/","mode":"proxy","enabled":true}'
```

`mode = "mirror"` is a background sync (the repository is a single whole
per repomd); `include` is not used for rpm-md.

## Caching proxy: .repo

`/etc/yum.repos.d/khrazhevnik.repo` (dnf) or
`/etc/zypp/repos.d/khrazhevnik.repo` (Zypper):

```ini
[khrazhevnik-fedora]
name=khrazhevnik proxy of Fedora
baseurl=http://<hrazhevnik>:29202/rpm/fedora/releases/$releasever/Everything/$basearch/os/
enabled=1
gpgcheck=1
```

`gpgcheck=1` works without changes: upstream signatures are preserved.

## Personal repository

Upload `.rpm/.drpm/.src.rpm` anywhere under the repository root EXCEPT
`repodata/` (it is generated — 400). Reindex creates
`repodata/primary.xml.gz` and `repodata/repomd.xml` plus the detached
signature `repodata/repomd.xml.asc` with the instance key. Client:

```sh
curl -sO http://<hrazhevnik>:29202/repo/<name>/key.asc
rpm --import key.asc
cat > /etc/yum.repos.d/<name>.repo << 'EOF'
[<name>]
name=<name> personal repo
baseurl=http://<hrazhevnik>:29202/repo/<name>
enabled=1
gpgcheck=1
EOF
dnf makecache && dnf install <package>
```

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                          | Class    | TTL      |
|----------------------------------------|----------|----------|
| `*.rpm`, `*.drpm`, `*.src.rpm`         | immutable| forever  |
| `repodata/repomd.xml` (+`.asc`,`.key`) | mutable  | 5m       |
| repodata with a hash in the name (`<sha>-primary.xml.gz`) | immutable | forever |
| other repodata (primary/filelists/other, `*.sqlite.bz2`, zck) | mutable | 5m |
| everything else (`media.1/*`)          | mutable  | 1m       |
