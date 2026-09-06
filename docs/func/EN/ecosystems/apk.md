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
http://<hrazhevnik>:29202/apk/alpine/v3.21/main
http://<hrazhevnik>:29202/apk/alpine/v3.21/community
```

## Personal repository

Upload `.apk` anywhere under the repository root; `APKINDEX.tar.gz` is
generated, and uploading it is forbidden. Reindex creates
`APKINDEX.tar.gz` (gzip+tar with the `APKINDEX` file in `K:V` format)
plus the detached signature `APKINDEX.tar.gz.sig` with the instance
key. Client:

```sh
curl -sO http://<hrazhevnik>:29202/repo/<name>/key.asc
cp key.asc /etc/apk/keys/<name>.pem    # apk accepts keys in /etc/apk/keys
echo 'http://<hrazhevnik>:29202/repo/<name>' >> /etc/apk/repositories
apk update && apk add <package>
```

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                        | Class    | TTL      |
|--------------------------------------|----------|----------|
| `*.apk`                              | immutable| forever  |
| `APKINDEX.tar.gz`, `APKINDEX.json` (+`.sig`) | mutable | 5m |
| `keys/*` (public keys)               | mutable  | 1h       |
| everything else                      | mutable  | 1m       |
