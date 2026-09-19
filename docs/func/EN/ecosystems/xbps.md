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

# xbps (Void Linux)

The URL prefix is `xbps`. The Void layout is flat: the repository root
holds the `<arch>-repodata` index and `<pkgver>.<arch>.xbps` packages with
their `.xbps.sig2` signatures. Packages are content-addressed by
name+version — an immutable cache kept forever; `<arch>-repodata` is
revalidated with a short TTL. Upstream metadata is served byte-for-byte —
`.sig2` signatures are valid.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"void","ecosystem":"xbps","base_url":"https://repo-default.voidlinux.org/current","mode":"proxy","enabled":true}'
```

`mode = "mirror"` is a background sync; `include` is a list of
architectures (for example `["x86_64","aarch64"]`). The index of each
architecture is `<arch>-repodata`; there is no common root index, so an
empty `include` is an error (as with apk). `noarch` packages enter every
arch group and are downloaded only once when several architectures are
mirrored.

## Caching proxy: /etc/xbps.d

```
# /etc/xbps.d/00-repository-main.conf
repository=http://<Khrazhevnik>:29202/xbps/void
```

A file with the same name in `/etc/xbps.d` overrides the system one in
`/usr/share/xbps.d` (xbps.d(5)) — the only configured repository is
`void`, so the client cannot bypass the proxy. If the remote's `include`
is limited, the index of the requested architecture is absent upstream
and the request returns 404.

## Signing

Each package carries a detached `.xbps.sig2` signature: RSA-4096,
PKCS#1 v1.5 over SHA-256 (the raw package body bytes). The `repodata`
itself is not signed (there is no `<arch>-repodata.sig2`): the public key
(PEM-SPKI) is embedded in the `index-meta.plist` entry inside the
container, and the client performs a TOFU key import with a prompt. The
legacy `.sig` next to `.sig2` is not covered by the index and is not
served as an indexed object; if requested directly, the proxy serves it
as immutable.

## Personal repository

Upload `.xbps` anywhere under the repository root (names are
`<pkgver>.<arch>.xbps`); `<arch>-repodata` is generated, and uploading it
is forbidden. Reindex creates `<arch>-repodata` (zstd level 9 + pax-tar:
`index.plist`/`index-meta.plist`/`stage.plist`), `noarch` packages enter
every arch group, and a `.sig2` is emitted for each package with the
instance key; the public key is embedded in `index-meta.plist`
(base64 PEM). A package whose props entry does not match its filename
fails the reindex task with an honest error. Client:

```sh
# TOFU key import: on first access xbps-install asks for the
# fingerprint — verify it against the PEM from xbps-key before confirming.
curl -s http://<Khrazhevnik>:29202/repo/<name>/xbps-key
echo 'repository=http://<Khrazhevnik>:29202/repo/<name>' \
  > /etc/xbps.d/00-repository-main.conf
xbps-install -S <package>
```

The instance public key is served at `GET /repo/<name>/xbps-key` (PEM) —
the fingerprint verification point during TOFU import; without a live
signer the route is not registered (404). For details, see
[personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path              | Class    | TTL      |
|----------------------------|----------|----------|
| `*.xbps`                   | immutable| forever  |
| `*.xbps.sig2`, `*.sig`     | immutable| forever  |
| `*-repodata` (in the root) | mutable  | 5m       |
| everything else            | mutable  | 1m       |
