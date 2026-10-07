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

# pacman (Arch Linux)

The URL prefix is `pacman`. Packages are content-addressed by NEVRA in
the name — an immutable cache; repository databases `{repo}.db`
are revalidated with a short TTL. Upstream metadata is served
byte-for-byte — `.sig` signatures are valid.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"arch","ecosystem":"pacman","base_url":"https://geo.mirror.pkgbuild.com","mode":"proxy","enabled":true}'
```

`mode = "mirror"` is a background sync; `include` is a list of
`repo/arch` pairs (for example `["core/x86_64","extra/x86_64"]`); an
empty `include` is an error (pacman has no root index of repositories).

## Caching proxy: pacman.conf

`/etc/pacman.d/mirrorlist` — just a URL without repositories; pacman
substitutes `core/`, `extra/` itself:

```
Server = http://<Khrazhevnik>:29202/pacman/arch/$repo/os/$arch
```

## Personal repository

Upload `.pkg.tar.zst` anywhere under the repository root; `.db`,
`.files`, `.sig` are generated, and uploading them is forbidden. Legacy
`.pkg.tar.xz`/`.gz` are not accepted (400): the dependency whitelist
contains no xz/gz decoder — repack them (`zstd` over the unpacked
tar). Reindex creates `<repo-name>.db` (tar.zst with desc entries)
plus the detached signature `<repo-name>.db.sig` with the instance
key. Client:

```sh
curl -sO http://<Khrazhevnik>:29202/repo/<name>/key.asc
pacman-key --add key.asc
pacman-key --lsign-key <fingerprint>   # required: otherwise the key is "unknown trust"
```

`/etc/pacman.conf`:

```ini
[<name>]
SigLevel = Never DatabaseRequired
Server = http://<Khrazhevnik>:29202/repo/<name>
```

`Never DatabaseRequired` — the database signature is required (the
generator emits `<repo-name>.db.sig` with the instance key, verified
through GnuPG), while package signatures are not demanded: **packages in
personal repositories are not signed** — the generator signs metadata
only. The Arch canon `SigLevel = Required DatabaseOptional` does NOT work
for such a repository: with `Required` on packages pacman fetches
`<package>.pkg.tar.zst.sig`, which the repository does not serve (404),
and fails with "failed to commit transaction" (live probe 2026-10-07,
`archlinux:latest`). Importing the key is not enough either: with
`pacman-key --add` and no `--lsign-key` the answer is
`signature from "Khrazhevnik <repo@localhost>" is unknown trust`.

If no key is imported at all, the workaround is `SigLevel = Never
DatabaseNever` (nothing is verified — a working, but NOT safe
configuration).

**Changing the instance key breaks verification until reindex:** `key.asc`
already serves the new key while `.db.sig` is signed with the previous
one — the client reports `error: <repo>: key "<fpr>" is unknown` and goes
looking for the key on an external keyserver (there is none in a
sovereign environment). Diagnose with `gpg --list-packets
<repo-name>.db.sig` (issuer fpr) versus `gpg --show-keys key.asc`; cure
it with a reindex of every repository of the instance. Instances created
before v1.3.1 regenerate the instance key at startup (EdDSA legacy —
GnuPG does not understand the former alg 27), so they need a reindex
unconditionally and their clients need to re-import `key.asc`.

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                       | Class    | TTL      |
|-------------------------------------|----------|----------|
| `*.pkg.tar.zst|.xz|.gz` (+`.sig`)   | immutable| forever  |

| `{repo}.db`, `{repo}.files` (+`.sig`, legacy `.tar.*`) | mutable | 5m |
| `keys/*` (public keys)              | mutable  | 1h       |
| everything else                     | mutable  | 1m       |
