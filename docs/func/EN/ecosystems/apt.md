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

# apt (Debian / Ubuntu)

The URL prefix is `apt`. The path after `/<remote>/` is forwarded to the
upstream byte-for-byte: InRelease signatures and checksums remain valid,
and upstream keys do not change.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

`mode = "mirror"` is a background sync of the entire repository (planned:
`sync_interval`, manual start via `POST /remotes/{id}/sync`). For mirror
mode, `include` is mandatory — a list of dists with an optional
component: `["stable"]`, `["stable/main"]`,
`["bookworm","bookworm-updates"]`. An empty `include` is an error for
apt (apt has no root index of dists).

## Caching proxy: sources.list

The classic format (`/etc/apt/sources.list` or
`/etc/apt/sources.list.d/khrazhevnik.list`):

```
deb http://<hrazhevnik>:29202/apt/debian stable main
```

deb822 (`/etc/apt/sources.list.d/debian.sources`):

```
Types: deb
URIs: http://<hrazhevnik>:29202/apt/debian
Suites: stable
Components: main
```

Upstream signatures are valid — `trusted=yes` is not needed, and the
keyring does not change.

## Personal repository

Upload `pool/...` (`.deb/.udeb/.ddeb/.dsc/.orig.tar.*/.debian.tar.*`);
uploading `dists/*` is forbidden (it is generated). Reindex creates
`dists/stable/main/binary-amd64/Packages` (+`.gz`, by-hash) and
`dists/stable/Release` plus the `InRelease`/`Release.gpg` signatures
with the instance key. Client:

```sh
curl -sO http://<hrazhevnik>:29202/repo/<name>/key.asc
echo 'deb [signed-by=/root/key.asc] http://<hrazhevnik>:29202/repo/<name> stable main' \
  > /etc/apt/sources.list.d/<name>.list
apt-get update && apt-get install <package>
```

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                         | Class    | TTL      |
|---------------------------------------|----------|----------|
| `pool/*`, `by-hash/*`                 | immutable| forever  |
| `dists/*` (Release, Packages*, dep11, cnf, i18n) | mutable | 5m |
| everything else                       | mutable  | 1m       |

Mutable indexes are revalidated via ETag/Last-Modified (a conditional
request to the upstream); on its 5xx with `stale_if_error` enabled, the
stale copy is served with `X-Cache: STALE`.
