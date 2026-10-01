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
their `.xbps.sig2` and `.xbps.sig` signatures. Packages are
content-addressed by
name+version — an immutable cache kept forever; `<arch>-repodata` is
revalidated with a short TTL. Upstream metadata is served byte-for-byte —
`.sig2`/`.sig` signatures are valid.

## Package format

`.xbps` is a tar archive compressed as a whole: zstd (the `xbps-create`
default since 0.59), gzip, or raw tar. Inside are `./props.plist` (the
package fields), `./files.plist`, and the payload files. An ar container
(`!<arch>`) does not exist in `.xbps` — ar parsing is not supported; xz is
an honest error (`ErrUnsupportedCompression`), left to a separate
micro-session modelled on 103. Only `./props.plist` is read (the name must
carry the canonical `./` prefix), the payload is never pulled into memory,
and a personal repository's reindex is built from its fields;
decompression is capped at 1 GiB and the `props.plist` body at 1 MiB.

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
mirrored. A sync pulls packages together with both signatures (`.sig2` and
`.sig`), so the mirror serves a live client completely.

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

Each package carries TWO detached signatures, exactly as upstream Void does:

- `.xbps.sig2` — RSA-4096, PKCS#1 v1.5 over the package's SHA-256 (the raw
  body bytes, as `xbps-rindex` computes it), verified by
  `openssl dgst -sha256 -verify`;
- `.xbps.sig` — the same RSA signature, but with the DigestInfo tagged with
  the SHA-1 OID (`1.3.14.3.2.26`) while carrying the package's SHA-256 digest
  (`openssl pkeyutl -verifyrecover` shows `30 2d 30 09 06 05 2b 0e 03 02 1a
  05 00 04 20` + `sha256(package)`). It is `.sig` that a live client requests
  with `signature-type: rsa`, and it does not fall back to `.sig2` — without
  `.sig` the install fails with 404. `openssl dgst -sha256 -verify` on `.sig`
  legitimately fails with `bad signature`: that is not a format error.

The `repodata` itself is not signed (there is no `<arch>-repodata.sig2`): the
public key (PEM-SPKI) is embedded in the `index-meta.plist` entry inside the
container, and the client performs a TOFU key import with a prompt. Both
signatures are immutable objects: the proxy and the mirror serve them
byte-for-byte.

## Personal repository

Upload `.xbps` anywhere under the repository root (names are
`<pkgver>.<arch>.xbps`); `<arch>-repodata` is generated, and uploading it
is forbidden. Reindex creates `<arch>-repodata` (zstd level 9 + pax-tar:
`index.plist`/`index-meta.plist`/`stage.plist`), `noarch` packages enter
every arch group, and BOTH signatures — `.sig2` and the legacy `.sig` — are
emitted for each package with the instance key; the public key is embedded
in `index-meta.plist`
(base64 PEM). A package whose props entry does not match its filename
fails the reindex task with an honest error.

`<arch>-repodata` holds at most one entry per `PkgName`: of several
versions of one package the newest stays in `index.plist` (version order
follows the client, `xbps_cmpver`: revision `_N` is compared after the
version, `alpha`/`beta`/`pre`/`rc`/`pl` are modifiers, `~` is a skipped
byte), the others stay in storage and are protected by retention/pins —
upstream `xbps-rindex` behaves the same way. Otherwise the client
(proplib) silently keeps the last dictionary entry with that key, and the
winner is decided by the lexical order of storage keys rather than by
version order. Client (live probe 191 — void container, XBPS 0.59.1):

```sh
# TOFU key import: on the first sync the client asks "Do you want to
# import this public key? [Y/n]" and prints the fingerprint — verify it
# against the PEM from xbps-key before confirming.
curl -s http://<Khrazhevnik>:29202/repo/<name>/xbps-key
echo 'repository=http://<Khrazhevnik>:29202/repo/<name>' \
  > /etc/xbps.d/00-repository-main.conf
xbps-install -S            # sync + TOFU key import (exit 0)
xbps-install -y <package>  # downloads .sig and the package, installs it (exit 0)
```

A live client requests exactly two objects — `<pkgver>.<arch>.xbps.sig` and
the package itself (it does not fall back to `.sig2`), so both signatures
must be present in the repository.

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
