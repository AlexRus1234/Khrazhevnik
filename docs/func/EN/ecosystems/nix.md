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

# nix (binary cache)

The URL prefix is `nix`. A caching proxy for narinfo + nar.xz: the
content is addressed — an ideal immutable cache (`nar/<52
nix-base32>.nar.xz` is cached forever, `<32 nix-base32>.narinfo` is
revalidated once per hour).

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"cache","ecosystem":"nix","base_url":"https://cache.nixos.org","mode":"proxy","enabled":true}'
```

Or with the headless flag:

```sh
khrazhevnik -config khrazhevnik.toml -add-remote nix/cache=https://cache.nixos.org
```

`mode = "mirror"` is not supported for nix (`UnsupportedError` when a
sync is started): a full mirror of `cache.nixos.org` is tens of TB, not
a goal; pull-through "by usage" only. `include` is not used.

## Caching proxy: nix.conf

`/etc/nix/nix.conf` (or `~/.config/nix/nix.conf`):

```
substituters = http://<Khrazhevnik>:29202/nix/cache https://cache.nixos.org
trusted-public-keys = cache.nixos.org-1:6NCHbD9f... (kept from upstream)
```

Khrazhevnik is set as the **first** substituter: a cache hit is a HIT
without contacting the upstream; a miss is a transparent pull-through.
The fallback `https://cache.nixos.org` guarantees access if the proxy
is unavailable.

`trusted-public-keys` is **left untouched** — narinfo is served
byte-exact, upstream signatures (`Sig:`) are valid, and the client
verifies them with the same keys as for `cache.nixos.org`.

Verification:

```sh
nix-shell -p hello --substituters http://<Khrazhevnik>:29202/nix/cache
```

The `X-Cache` header: a nar is always `HIT` after the first request; a
narinfo is `MISS`/`HIT` per its 1h TTL. A 404 on a narinfo is a normal
situation for the nix client (substituter iteration): a correct 404 is
returned (not 502) and it is negative-cached.

## Personal repository

Upload: `<hash>.narinfo` (at the repository root) +
`nar/<fileHash>.nar.xz|.nar`: the hash is 32 nix-base32 characters (the
canonical nix alphabet: digits and Latin letters without `e`/`o`/`t`/`u`
— this is how nix itself encodes store path hashes); fileHash is 52
nix-base32 characters (the sha256 of the compressed file,
`(256−1)/5+1 = 52` — session 47); other paths yield 400.

Reindex **re-signs** narinfo: the `Sig` field is replaced with the
instance key (ed25519, format `name:signature` — 2 fields: the key
name and the base64 signature; what is signed is the PathInfo
fingerprint `1;StorePath;NarHash;NarSize;Refs`, not the file bytes),
everything else is byte-exact. This is the only place in the project
where a third-party file is modified; nar files are immutable and are
not touched. Client:

```
substituters = http://<Khrazhevnik>:29202/repo/<name> https://cache.nixos.org
trusted-public-keys = khrazhevnik:<pubkey-b64> cache.nixos.org-1:6NCHbD9f...
```

`<pubkey-b64>` = `GET /repo/<name>/nix-key.asc` — a single line
`khrazhevnik:<base64>` (the nix format, NOT armored OpenPGP — nix has
its own signature model). Without NarSigner (a degraded mode — only
for soft initialization errors: the module is not linked, a keygen
failure on an empty keys_dir) narinfo are served as is — upstream
signatures are valid if the client trusts them; corrupted key material
(`domain.KeyMaterialError`) is fatal — startup fails (session 40).

For details, see [personal-repos.md](../personal-repos.md).

## Object classification

| Upstream path                 | Class    | TTL      |
|-------------------------------|----------|----------|
| `nar/<52 nix-base32>.nar.xz`  | immutable| forever  |
| `nar/<52 nix-base32>.nar`     | immutable| forever  |
| `<32 nix-base32>.narinfo`     | mutable  | 1h       |
| `nix-cache-info`              | mutable  | 1h       |
| `log/<…>`                     | immutable| forever  |
| everything else               | mutable  | 1m       |

## Limitations

- Pull-through only; background sync is not supported.
- Personal repositories validate narinfo as 32 nix-base32 characters
  and nar as 52 (fileHash, session 47); the proxy classification uses
  the same lengths, and unmatched paths fall into the conservative
  mutable{TTL 1m} class.
- Narinfo is served byte-exact; re-signing and path patching are
  impossible (upstream signatures must remain valid) — except in
  personal repositories, where re-signing is precisely the function.
