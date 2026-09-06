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

# Personal repositories

A user's personal repository — `POST /api/v1/repos` (admin), then
package uploads via `PUT /api/v1/repos/{id}/objects/<path>` (the owner
or a `repo:<id>:write` scoped token) and `POST /api/v1/repos/{id}/reindex`
(an index generation background task). Reads are public:
`GET /repo/<name>/*` on port :29202.

Ecosystems supported in v1: apt, rpm-md, pacman, apk, nix. Each has
its own index generator (`mod/ecosystem/*/gen.go`, sessions 14/16) and
optional metadata signing with the instance key (session 15/16).
Client configuration per ecosystem — in [ecosystems/](ecosystems/);
this page covers the general publishing flow. Repositories can also be
managed from the [web admin UI](ui.md).

## General flow

```sh
# 1. Admin: create a repository (name is the URL slug, ecosystem is the adapter name).
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)
curl -s -X POST http://127.0.0.1:30202/api/v1/repos \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"alice","owner_id":2,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0}}'

# 2. Owner: a repo:<id>:write scoped token (or the owner's session).
REPOWRITE=$(curl -s -X POST http://127.0.0.1:30202/api/v1/users/2/api-tokens \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"repo-write","scopes":["repo:1:write"]}' | jq -r .token)

# 3. Upload packages (Content-Length is required — v1 streams with verification).
curl -s -X PUT "http://127.0.0.1:30202/api/v1/repos/1/objects/pool/main/f/foo/foo_1.0-1_amd64.deb" \
  -H "Authorization: Bearer $REPOWRITE" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @foo_1.0-1_amd64.deb

# 4. Reindex → 202 (a background task). Status check — /api/v1/tasks/{id}.
curl -s -X POST http://127.0.0.1:30202/api/v1/repos/1/reindex \
  -H "Authorization: Bearer $REPOWRITE"
```

After a reindex the indexes are publicly available:
`GET /repo/alice/<index-path>`.

**Key convention (v1):** upload and delete lowercase the path —
published objects are stored in lowercase (`/pool/Foo.deb` becomes
`pool/foo.deb` on upload); the public GET (`/repo/<name>/*`)
normalizes the request the same way, so apt clients requesting
capitalized indexes (`Packages`, `Release`) receive them without extra
configuration. The path arrives from the client percent-encoded (apt
sends "+" as `%2b`) — decoding happens before the key check, so `%2b`
and a raw `+` yield the same object; double encoding (`%252b`) — 400.
(The proxy cache of upstream objects is a different matter: there path
case is case-sensitive and preserved — `cache/apt/<id>/pool/Foo.deb`
and `.../pool/foo.deb` are different objects.)

## apt

- **Upload:** `pool/...` with the extensions
  `.deb/.udeb/.ddeb/.dsc/.orig.tar.*/.debian.tar.*`. `dists/*` is
  generated; uploading there is forbidden (400).
- **Indexes (reindex):** `dists/stable/main/binary-amd64/Packages`
  (+.gz + by-hash) + `dists/stable/Release` (Date/Suite/Components/
  Architectures/SHA256). Signature: `InRelease` (cleartext) +
  `Release.gpg` (detached) — with the instance OpenPGP key (ed25519).
- **Client:** `deb [signed-by=/path/to/key.asc] http://<Khrazhevnik>:29202/repo/alice stable main`,
  where `key.asc` = `GET /repo/alice/key.asc`.
- **Public key:** `GET /repo/<name>/key.asc` (armored OpenPGP).
- **By-hash retention:** index copies under `by-hash/sha256/<hash>`
  live for two Release generations (current + previous): a client that
  downloaded Release before a reindex keeps downloading by the old
  hashes without 404s. Generations older than two are removed at
  reindex; keeping more is up to the operator (manual cleanup of
  `dists/…/by-hash/sha256/*` keys).

## rpm-md (dnf / Zypper)

- **Upload:** `.rpm/.drpm/.src.rpm` anywhere under the repository
  root, EXCEPT `repodata/` (generated; uploading there is forbidden —
  400).
- **Indexes (reindex):** `repodata/primary.xml.gz` (name/arch/version/
  checksum/location/time/size) + `repodata/repomd.xml` (checksum/
  open-checksum/size/timestamp). Signature: `repodata/repomd.xml.asc`
  (detached, with the instance OpenPGP key).
- **Client:** `/etc/yum.repos.d/alice.repo`:
  ```ini
  [alice]
  name=alice personal repo
  baseurl=http://<Khrazhevnik>:29202/repo/alice
  enabled=1
  gpgcheck=1
  ```
  The key `GET /repo/alice/key.asc` is imported via `rpm --import`.
- **Public key:** `GET /repo/<name>/key.asc` (armored OpenPGP).

## pacman (Arch)

- **Upload:** `.pkg.tar.zst` anywhere under the repository root;
  `.db`, `.files`, `.sig` are generated; uploading them is forbidden.
  Legacy `.pkg.tar.xz`/`.gz` are not accepted (400): there is no xz/
  gz decoder in the dependency whitelist — repack as zst.
- **Indexes (reindex):** `<repo.Name>.db` (tar.zst with
  `<name>-<ver>-<arch>/desc` entries) + `<repo.Name>.db.sig`
  (detached, with the instance OpenPGP key).
- **Client:** `/etc/pacman.conf`:
  ```ini
  [alice]
  SigLevel = Required DatabaseOptional
  Server = http://<Khrazhevnik>:29202/repo/alice
  ```
  The key `GET /repo/alice/key.asc` is imported via `pacman-key --add`.
- **Public key:** `GET /repo/<name>/key.asc` (armored OpenPGP).

## apk (Alpine)

- **Upload:** `.apk` anywhere under the repository root;
  `APKINDEX.tar.gz` is generated; uploading it is forbidden.
- **Indexes (reindex):** `APKINDEX.tar.gz` (gzip+tar with an
  `APKINDEX` file in "K:V" format — C/P/V/A/F/...) +
  `APKINDEX.tar.gz.sig` (detached, with the instance OpenPGP key).
- **Client:** `/etc/apk/repositories`:
  ```
  http://<Khrazhevnik>:29202/repo/alice
  ```
  The key `GET /repo/alice/key.asc` is copied into `/etc/apk/keys/`.
- **Public key:** `GET /repo/<name>/key.asc` (armored OpenPGP).

## nix (binary cache)

- **Upload:** `<32 nix-base32>.narinfo` (at the repository root; the
  store path hash) + `nar/<52 nix-base32 fileHash>.nar.xz|.nar`
  (sha256 of the compressed file, (256−1)/5+1 = 52 characters —
  session 47). Any other paths — 400. The nix-base32 alphabet is
  canonical nix (`[0-9a-z]` without `e`/`o`/`t`/`u`; hex with `e` is
  not that alphabet).
- **Indexes (reindex):** narinfo files are **re-signed** with the
  instance Sig key (ed25519, "name:signature" format — 2 fields: the
  key name and the base64 signature of the PathInfo fingerprint).
  This is the only place in the project where we MODIFY a foreign
  file: only the Sig field is replaced, the rest is byte-exact (a
  golden diff test). nar files are immutable and are not touched.
- **Client:** `/etc/nix/nix.conf`:
  ```
  substituters = http://<Khrazhevnik>:29202/repo/alice https://cache.nixos.org
  trusted-public-keys = khrazhevnik:<pubkey-b64> cache.nixos.org-1:6NCHbD9f...
  ```
  `<pubkey-b64>` = `GET /repo/alice/nix-key.asc` (a single
  `khrazhevnik:<base64>` line).
- **Public narinfo key:** `GET /repo/<name>/nix-key.asc` (format
  `name:pubkey-b64`, NOT armored OpenPGP — nix has its own signature
  model).
- **Without NarSigner** (degraded mode): narinfo files are served as
  is (upstream signatures are valid if the client trusts them — see
  [ecosystems/nix.md](ecosystems/nix.md)). Degradation applies only to
  soft initialization errors (the module is not linked, a keygen
  failure on an empty `signing.keys_dir`); broken key material
  (`domain.KeyMaterialError`) is fatal — startup fails (session 40).

## Manual release checklist

Before the v1.0.0 release, personal repositories of all 5 ecosystems
are verified by hand with real package managers
(apt/dnf/zypper/pacman/apk/nix): a package install from a signed
repository with signature validation. The full checklist —
[docs/RELEASE.md](../../RELEASE.md). CI only exercises the format with
parsers (the same parsers verify their own generators — roundtrip);
real clients are a manual checklist (impossible in CI:
nested-podman).
