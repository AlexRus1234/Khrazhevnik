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
byte-for-byte — upstream signatures are valid.

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
root). `noarch` entries are included in the index of EVERY architecture
(a client reads only its own index and fetches the file from `/noarch/`).
No index is generated at the repository root (a previously written one is
not deleted — remove it by hand).

The index is signed with the instance key INSIDE the file — exactly as
Alpine does it: the first gzip member is a tar with the single member
`.SIGN.RSA.khrazhevnik.rsa.pub` (the raw bytes of an RSA PKCS#1 v1.5
signature over the SHA-1 DigestInfo of the sha1 of the COMPRESSED bytes of
the second, body member `APKINDEX.tar.gz`), and the second member is the
index itself. The archive is a single continuous tar across the member
boundary (the trailing zero blocks of tar live only in the body), so both
our parser and apk see both members. There is no separate
`APKINDEX.tar.gz.sig` any more: apk never requests it — the Alpine CDN
answers 404 for it too, the signature always sits as the first member
inside `APKINDEX.tar.gz`. The format was checked byte-for-byte against the
Alpine reference (`openssl pkeyutl -verifyrecover` over the `.SIGN.RSA.…`
member of the edge/main/x86_64 index: DigestInfo = the `sha1` OID
(`3021300906052b0e03021a05000414`) + the 20-byte digest; the digest matched
the sha1 of the COMPRESSED tail from the first member boundary and did NOT
match the sha1 of the decompressed tar). `--allow-untrusted` is not needed:
the client verifies the signature and installs normally (live probe 195 —
alpine:3.21 apk-tools 2.14.6 and alpine:edge 3.0.7, `apk update` /
`apk add` / `apk fetch` — exit 0 without the flag).

The client key — `GET /repo/<name>/apk-key` (SPKI-PEM, the same instance
key as `xbps-key`). The file name in `/etc/apk/keys/` must match the
`<keyid>` from the tar member name (`.SIGN.<algorithm>.<keyid>` — apk takes
the keyid to be exactly the file name): ours is `khrazhevnik.rsa.pub`. A
wrong format or file name is diagnosed only as
`WARNING: updating and opening <repo>: UNTRUSTED signature`. Client (live
probe 195):

```sh
curl -sO http://<Khrazhevnik>:29202/repo/<name>/apk-key
cp apk-key /etc/apk/keys/khrazhevnik.rsa.pub   # name = keyid from .SIGN.RSA.<keyid>
echo 'http://<Khrazhevnik>:29202/repo/<name>' >> /etc/apk/repositories
apk update                            # exit 0
apk add <package>                     # exit 0 — the package installs and runs
```

There is no need to put the architecture into the
`/etc/apk/repositories` line — the client appends its own and requests
`<repo-url>/<arch>/APKINDEX.tar.gz`. Boundary: the rule holds for the
indexes reindex writes; upstream indexes are served byte-for-byte by the
caching proxy together with their own signatures. The entry's `C:`
field is `Q1` + base64 of the sha1 over the COMPRESSED bytes of the `.apk`
control section (the gzip member carrying `./.PKGINFO`), exactly as
apk-tools computes it: anything else is rejected by the client on the
checksum (`BAD signature` in 2.x / `v2 package integrity error` in 3.x).
The invariant is verified live on a real Alpine package
(`tree-2.2.1-r0` from v3.21: `C:` matched the upstream APKINDEX) and by
`apk add` in alpine:3.21 and alpine:edge. `S:` is the size of the whole
file. Boundary: the rule is verified for gzip v2 packages; for `.apk` v3
(zstd/raw tar) the generator still writes the sha1 of the WHOLE file — the
`C:` semantics of apk-tools 3.x for that layout are unverified (finding of
session 193, a separate micro-session).

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                        | Class    | TTL      |
|--------------------------------------|----------|----------|
| `*.apk`                              | immutable| forever  |
| `APKINDEX.tar.gz`, `APKINDEX.json`     | mutable | 5m |
| `keys/*` (public keys)               | mutable  | 1h       |
| everything else                      | mutable  | 1m       |
