<!--
Khrazhevnik — caching proxy and mirror for Linux package repositories
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

The URL prefix is `apk`. Packages are content-addressed by
name+version — an immutable cache kept forever; `APKINDEX.tar.gz` is
revalidated with a short TTL. Upstream metadata is served
byte-for-byte — `.sig` signatures are valid.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"alpine","ecosystem":"apk","base_url":"https://dl-cdn.alpinelinux.org/alpine","mode":"proxy","enabled":true}'
```

`mode = "mirror"` is a background sync; `include` is a list of
architectures (for example `["x86_64","aarch64"]`); an empty `include`
is an error (apk has no root index of architectures).

## Caching proxy: /etc/apk/repositories

```
http://<Khrazhevnik>:29202/apk/alpine/v3.21/main
http://<Khrazhevnik>:29202/apk/alpine/v3.21/community
```

## Personal repository

A package goes into the directory of its architecture:
`<architecture>/<file>.apk` (`arch` from `.PKGINFO`); an `arch = noarch`
package goes into `noarch/`. Any other path (including the repository root)
— `400 validation_error`. Reindex writes one index per architecture —
`<architecture>/APKINDEX.tar.gz` (gzip+tar with the `APKINDEX` file in
`K:V` format; the `F:` field is the actual package path from the repository
root) and the detached signature
`<architecture>/APKINDEX.tar.gz.sig` with the instance key. `noarch`
entries are included in the index of EVERY architecture (a client reads
only its own index and fetches the file from `/noarch/`). No index is
generated at the repository root (a previously written one is not deleted —
remove it by hand). Client:

```sh
curl -sO http://<Khrazhevnik>:29202/repo/<name>/key.asc
cp key.asc /etc/apk/keys/<name>.pem    # apk accepts keys in /etc/apk/keys
echo 'http://<Khrazhevnik>:29202/repo/<name>' >> /etc/apk/repositories
apk update --allow-untrusted && apk add --allow-untrusted <package>
```

There is no need to put the architecture into the
`/etc/apk/repositories` line — the client appends its own and requests
`<repo-url>/<arch>/APKINDEX.tar.gz`. `--allow-untrusted` is needed while
the index signature is not accepted by the client (`UNTRUSTED signature` —
a deferred personal apk repository signing question). Installing a package
from a personal repository is still rejected by the client on the checksum
check (`BAD signature` in apk-tools 2.x / `v2 package integrity error` in
3.x: the generator writes `C:` as the sha1 of the whole file, while
apk-tools treats that field as the sha1 of the control section) — a known
index defect, not a layout one.

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                        | Class    | TTL      |
|--------------------------------------|----------|----------|
| `*.apk`                              | immutable| forever  |
| `APKINDEX.tar.gz`, `APKINDEX.json` (+`.sig`) | mutable | 5m |
| `keys/*` (public keys)               | mutable  | 1h       |
| everything else                      | mutable  | 1m       |
