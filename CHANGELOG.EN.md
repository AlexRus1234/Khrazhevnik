<!--
Khrazhevnik — cache proxy and mirror of linux repositories
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

# Changelog (English translation)

Format — [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning — semver. The canonical file is
[CHANGELOG.md](CHANGELOG.md) (Russian); this file is its translation
and may lag slightly behind. Pre-1.0.0 development history (in
Russian) — [CHANGELOG.old.md](CHANGELOG.old.md).

## [Unreleased]

### Added

- Admin API: per-upstream proxy — the `proxy_url` field in
  POST/PATCH/GET `/api/v1/remotes` (tri-state: empty — inherit the
  global proxy, `direct` — no proxy, otherwise an
  http/https/socks5/socks5h URL with optional userinfo); an invalid
  value yields 400 validation_error; the proxy password never reaches
  the audit log — the detail carries the masked URL
  (`socks5://***@h:1080`).
- Admin API: global upstream proxy — GET/PUT
  `/api/v1/settings/upstream-proxy` (`{"value": …}` body; empty —
  env proxies HTTP_PROXY/HTTPS_PROXY/NO_PROXY as the fallback,
  `direct`, otherwise a valid URL); an invalid value yields 400
  validation_error; `settings.update` audit entry with the masked
  URL. Applied without a restart within 30s (lazy TTL cache of the
  transport factory).
- Web UI: per-remote proxy controls (tri-state: inherit the global
  proxy / direct / custom URL) and the global upstream proxy on the
  Remotes page; the table shows the effective mode.
- Admin API: tabular export/import of remotes — GET
  `/api/v1/remotes/export` (a `text/plain` file with
  Content-Disposition) and POST `/api/v1/remotes/import` (line by line,
  body ≤256 KiB and ≤1000 lines). Import returns 200 with a
  `{created, skipped, errors}` report: name duplicates (already in the
  DB or within the file) and broken lines are skipped with a report,
  valid lines are created; `remote.import` audit entry with counters.
- Web UI: an Export button on the Remotes page downloads the current
  remote list as `khrazhevnik-remotes.txt` (blob + `<a download>`).
- Web UI: a remote import panel on the Remotes page — paste
  line-formatted text or choose a `.txt` file; a
  created/skipped/errors report per line and a table refresh.

### Fixed

- Binary: graceful shutdown flake — exit 1 instead of 0 on SIGTERM
  (`khrazhevnik: context deadline exceeded`): Shutdown waits for
  StateNew connections (client keep-alive pools) ~5s per
  golang/go#22682, the default HTTP budget was exactly 5s — a coin
  flip. The binary's budget is raised to 10s
  (`web.Server.ShutdownTimeout`; the in-process integration tests
  already carried 10s since the TestWireBootShutdown flake fix, the
  binary was the only carrier of the default). Reproduction:
  TestBinarySmoke 5/50 red under `-race` (golang:1.27, local
  container) → 0/50 after the fix. The container contract
  «SIGTERM → exit 0» is restored.
- CI: flaky «сервер: context deadline exceeded» in integration tests
  (TestAdminMetricsLive/TestWireBootShutdown and everything sharing
  the pattern) — Shutdown waits ~5s for StateNew connections
  (accepted by the client, no request yet) per golang/go#22682, and
  with a budget of exactly 5s it returned DeadlineExceeded on a coin
  flip. web.Server.shutdownTimeout is exported as ShutdownTimeout,
  integration envs now use 10s — the grace period fits inside the
  budget; the «Run returns nil after cancel» contract is not relaxed.
  Reproduction: 12/100 red on TestWireBootShutdown → 0/100 after the
  fix (go test -race, local).
- CI: mariadb contract suites on the mariadb:13 image — migration 0006
  failed («Can't DROP FOREIGN KEY `api_tokens_ibfk_1`»): server 13
  auto-names an unnamed FK as `1`, not `<table>_ibfk_N`; both
  candidates are now dropped under `IF EXISTS` (MariaDB syntax, not
  MySQL), the new constraint keeps its explicit name. Reproduced
  against a local mariadb:13 — red → green (the whole
  TestCatalogContractMariaDB).
- Web: the «Copy» button next to a freshly issued API token did not
  work outside a secure context (admin UI served over http on LAN:
  `navigator.clipboard` is undefined, the TypeError was silently
  swallowed — the button «did nothing»); a fallback via a hidden
  textarea + `document.execCommand('copy')` is added, and if both
  paths fail a «Copy failed…» line is shown under the button. The
  «Copied» label now clears itself after ~2s (previously it hung
  until the next token issue).

### Changed

- Toolchain and CI updated to current versions: Go 1.26.3 → 1.27.1
  (go.mod `go 1.27` + `toolchain go1.27.1`), golangci-lint 1.64.8 →
  2.13.2 (config migrated to the v2 format), actions/checkout v4 → v7.
- CI images updated: service postgres 16 → 18 and mariadb 11 → 13;
  build images node:22-alpine → 24-alpine and golang:1.26-alpine →
  1.27-alpine; the debian distro leg bookworm → trixie. Job containers
  and the fedora leg stay on fedora:44 (current release; the branched
  46 image on quay is not a release). The minio pin is untouched —
  the pinned tag remains the latest community release on quay.
- CI: the S3 service of the contract suites replaced MinIO → SeaweedFS
  (docker.io/chrislusf/seaweedfs:4.47, pinned): minio/minio on Docker
  Hub is gone (community publications ended, 2025-10) and the quay
  image was fetched bypassing Nora — seaweedfs goes through it, like
  postgres/mariadb. The intermediate candidate rustfs:1.0.0 was
  rejected: its container died with SIGSEGV (exit 139) mid-run (runs
  be8c1fa/58aac96 — «lookup rustfs: no such host» for 200s+: the dead
  container's teardown removes the DNS entry; local reproduction —
  death after the first suite run; 1.0.0-alpha.67 is stable, we will
  revisit rustfs once its releases settle). SeaweedFS setup: cmd goes
  through the native /entrypoint.sh ('server' case; the runner's act
  fork ignores --entrypoint from options — the container died
  Exited(2) on «weed -c»), NO s3.json: the anonymous mode rejects only
  signed requests, and minio-go with empty credentials (env
  KHRZ_TEST_S3_*_KEY) sends unsigned ones; -volume.max=1000 (the
  default is 8, and SeaweedFS grows a volume per almost every object
  assign — one suite run ≈ 100 volumes). Production code is untouched
  (minio-go); suite+soak 18/18 green locally.
- CI: a service availability gate (s3/postgres/mariadb) before the
  build: name resolution up to 60s + the TCP path to S3; a dead
  service (like the rustfs SIGSEGV incident) or a lost aardvark-dns
  registration of the job network yields an early ::error with runner
  diagnostics instructions instead of 200s+ of minio-client noise in
  the test phase. Service order is not controllable (act iterates a Go
  map).

## [1.2.1] — 2026-09-19

### Changed

- CI: the distro-test Cleanup now prunes old images
  (`podman image prune -f --filter until=2h`) — the runner runs out of
  disk space (`cmd/go` crashing with SIGBUS in telemetry mmap when the
  disk fills up); the filter leaves fresh images of parallel jobs alone.

### Fixed

- CI: the void distro-test leg — the `voidlinux/voidlinux:latest` image
  lags the upstream snapshot, so `xbps-install` refused to install a
  package ("The 'xbps' package must be updated", exit 16); index sync and
  a manager self-update now precede the target package
  (`xbps-install -S -y`; `xbps-install -u -y xbps`).
- Config: `xbps` added to `knownEcosystemNames` — without it the
  ecosystem was absent from the default config, the adapter was never
  wired, and any `/xbps/...` returned an instant 404 bypassing upstream
  (an oversight of session 129; surfaced by the first real run of the
  void distro-test leg).

### Changed

- Docs: the ROADMAP "Current status" section synced with the released
  v1.2.0 (2026-09-19) — the status section was not updated in release
  session 147.
- Docs: ROADMAP — ecosystem expansion (pkg/Guix/Flatpak) deprioritized;
  the post-v1 focus is functional directions (owner decision,
  2026-09-19).
- Docs: ROADMAP — post-v1 priorities set (owner decision, 2026-09-19):
  high — personal-repo retention → cache-proxy eviction (the "object
  lifecycle" wave), medium — notifications, low — the remaining
  directions, lowest — ecosystem expansion.

## [1.2.0] — 2026-09-19

### Added

- **xbps (Void Linux) — caching proxy and mirror:** the sixth ecosystem —
  the `/xbps/` prefix, case-sensitive classification (packages `*.xbps`
  and signatures `*.sig2`/`*.sig` are immutable forever, the root
  `<arch>-repodata` is mutable 5m, everything else mutable 1m). Proxy:
  metadata and packages byte-exact, a repeated request returns
  `X-Cache: HIT`, mutable index revalidation (304 without a body),
  negative-cache 404. Mirror: `Enumerate` over the include architectures
  (`<arch>-repodata`), package paths `<pkgver>.<arch>.xbps` built by
  `Filename()`, noarch included once (deduplicated), the SHA256 from
  `filename-sha256` (64 hex) populates the remote checksum table
  (`Target.Checksum`); sync with a resume diff, a body with a wrong sha256
  fails the sync and does NOT commit the object (Abort, §4 invariant), a
  partial sync does not overwrite the table.
- **xbps — metadata and package parsers (streaming + fuzzing):** the
  `<arch>-repodata` container (zstd+tar: `index.plist` as a stream,
  `index-meta.plist` as bytes, `stage.plist` skipped; 1 GiB decompression
  / 64 KiB meta caps); the XML-plist `index.plist` parser (the
  `pkgname` → fields dictionary via a callback, caps of 64 KiB per field /
  4096 array elements / 1M records, unknown keys skipped — proplib forward
  compatibility); the pkgver parser (`SplitPkgver`/`SplitRevision`/
  `Filename` — dashes/`++`/`~`, an `_N` revision made of digits only); the
  `.xbps` ar parser (zstd/gzip/raw by magic, only `props.plist`, a 1 MiB
  cap; xz becomes `ErrUnsupportedCompression`). Typed format errors
  (`ErrBadPlist`/`ErrBadZstd`/`ErrBadTar`/`ErrBadAr`/`ErrPropsMissing`/…).
  Fuzzing `FuzzParseRepoData`/`FuzzOpenPackage`/`FuzzSplitPkgver` plus the
  golden fixture `repodata-golden.zst` with real Void names (`0ad`,
  `libstdc++`, `libxml2`, `python3-pip`, `Mustache`).
- **xbps — instance RSA signer and key endpoint:** `port.RsaSigner` +
  `port.RsaSignerInjector` and the `mod/sign/rsasha256` module (RSA-4096,
  PKCS#1 v1.5 over SHA-256 — the `.sig2` format): the private key
  `xbps-rsa.key` (PKCS#1 PEM, 0600, atomic, no overwrite), the public one
  as SPKI-PEM (`PUBLIC KEY`) for index-meta and serving; no passphrase,
  corrupt key material is fatal at start. `GET /repo/<name>/xbps-key`
  serves the PEM for fingerprint verification during TOFU import
  (registered only when a signer is live, an unknown repo is a 404), plus
  an “xbps” block on the “Keys” screen.
- **xbps — personal repositories (generator, writer, integration):** the
  streaming `index.plist` writer (XML-plist via `encoding/xml` tokens,
  deterministic reindex: records by `pkgname`, fields alphabetically,
  empty ones omitted; lossless roundtrip with the parser) and the
  generator — an `xbps-rindex --add --sign --sign-pkg` analogue: flat
  `.xbps` → `<arch>-repodata` (zstd level 9 + pax-tar) + a `.sig2` for
  each package (RSA/SHA-256 with the instance key), noarch enters every
  arch group, the public key embedded in index-meta (base64 PEM); without
  a key — repodata without `.sig2`, a mismatched filename or a broken
  package is an honest task error. End-to-end (integration): upload
  `.xbps` → reindex → `<arch>-repodata` (parsed by the same parsers) and
  `.sig2` (verified with `crypto/rsa` against `/xbps-key`); a repeated
  reindex yields a byte-identical index.
- **xbps in the UI and SPECIFICATION:** ecosystem selection on the
  remotes/repos screens, config, key endpoint and generator in the
  specification.

### Changed

- **Docs (session 128):** the XBPS ROADMAP is brought in line with the
  format facts — a flat layout (`<arch>-repodata` in the root, not
  `current/<arch>/`), `.sig2` signatures are RSA-4096 PKCS#1 v1.5/SHA-256
  (not ed25519), the key is embedded in `index-meta.plist` (client-side
  TOFU import); the v1.2 wave lives in the `v1.2.0dev` branch.
- **CI (session 144):** distro-test — the sixth leg: void
  (`xbps-install` through the proxy, `xbps/<remote>`, hermeticity via
  `/etc/xbps.d`); the RELEASE checklist is synced (6/6 legs, xbps items
  in §1/§2).
- **Docs (session 146):** xbps functional documentation
  (`docs/func/ru|EN/ecosystems/xbps.md`), TESTING sync (cases/coverage),
  ARCHITECTURE (ecosystems, `mod/sign/rsasha256`, publish and checksum
  invariants), HISTORY (wave section), ROADMAP (v1.2.0 status, XBPS
  removed from post-v1), README.

## [1.1.0] — 2026-09-17

### Added

- **API:** password change — `POST /api/v1/auth/password` (self: the old
  password is verified, the response carries a fresh JWT; under the
  common login rate limit, audited as `user.password.change`) and
  `POST /api/v1/users/{id}/password` (admin: no old password, 204;
  audited as `user.password.set`). Both bump `token_version`: JWT
  sessions die, `khz_` tokens survive (session 67 precedent).
- **UI:** password change in the “Users” section (session 126) — a
  “Change your password” block (current/new + confirmation,
  `minlength=8`) that swaps the token on the fly (the session survives),
  plus a “Change password” action for an admin over a user; i18n ru/en,
  an e2e smoke of signing in with the new password.
- **Storage:** periodic sweeping cleanup (storagegc, sessions 119–120) —
  orphaned versions of mutable cache objects and `repo/<id>/` objects of
  deleted repositories; knobs `storage.gc_interval` (default `24h`,
  `0` = disabled) and `storage.gc_grace` (default `168h`, strictly
  `> 0`), metrics `khrazhevnik_storage_gc_*` (runs/deleted/bytes/failed/
  duration). The keeper goroutine is stopped in the shutdown cascade
  without a final pass.
- **API:** manual run of the sweeping storage cleanup —
  `POST /api/v1/storage/gc` (admin, audited as `storage.gc`): a
  background task (kind=`gc`, label=`storage`), 202 + `task_id`;
  `?dry_run=1|true` — a revision pass without deletions (candidate
  counters in the task log); 409 while the task is active, 429 on the
  worker limit, 503 without the cleanup module.

### Changed

- **DB:** index `idx_sync_jobs_remote_id` on `sync_jobs(remote_id)`
  (migration 0008, all three dialects); `JobStore.JobByRemote` — a
  point lookup instead of a full `Jobs()` scan in
  `mirror.findJobByRemote` (called on every `touchJob` of an active
  sync, `ProgressInterval=2s`). Fulfills the ROADMAP promise of a
  `sync_jobs` remote_id index.
- **Repositories:** `DELETE /api/v1/repos/{id}` now sweeps the
  `repo/<id>/` objects out of storage immediately — via a background
  task (kind=`gc`, label=`repo-<id>`) instead of accumulating an orphan
  prefix until the next sweeping cleanup. A task failure does not fail
  the DELETE: the periodic sweep picks up the remainder. Synchronous
  deletion in the handler was rejected — on s3 thousands of Deletes
  would hold the HTTP request for minutes.

## [1.0.3] — 2026-09-13

### Fixed

- **DB (mariadb):** the transient `1467 ER_AUTOINC_READ_FAILED` error
  during the bootstrap-user race (`EnsureFirstUser`) no longer escapes —
  it is now treated as an InnoDB retryable conflict (1213/1205): the
  losing writer re-runs `INSERT…SELECT WHERE NOT EXISTS` and sees the
  winner's row (`RowsAffected=0`). It surfaced as an intermittent
  `Error 1467 (HY000): Failed to read auto-increment value from storage
  engine` on 20 concurrent `EnsureFirstUser` calls (contract suite;
  reproduced over a 400-iteration run, fixed by the retry).

- **Range serving (206/416):** the proxy and the personal-repo public
  port (:29202) understand HTTP Range — a single slice `206` with an
  exact `Content-Range`, `multipart/byteranges` up to 256 ranges (cap =
  librepo's initial `max_ranges`), `416` with `Content-Range: bytes */N`,
  `Accept-Ranges: bytes` on 200/206 of the Range path, `If-Range` (a
  strong ETag or a `Last-Modified` date), garbage Range → 200 full
  (RFC 9110 MAY). A slice is byte-exact — the byte-exact serving
  invariant is extended to substrings. Fixes dnf5 failing behind the
  proxy on zchunk metadata (`primary data not present`): dnf5/librepo
  downloads `.zck` as ranges. The storage port gained `GetRange`
  (fs + s3), the engine — `FetchMeta`/`OpenBody`/`OpenRange` (resolve
  without opening the body, one resolve per client request). Metric
  `khrazhevnik_cache_range_responses_total{ecosystem}`; the distro-test
  fedora leg became mandatory and verifies the 206 fact after
  `dnf install` (verify-range).

### Changed

- **Proxy and :29202:** HEAD requests with Range return the 206/416
  headers without opening the body — byte counters are honest (0 body
  bytes); the single point of Range semantics is `web.serveRanged` for
  the proxy and personal repositories.

## [1.0.2] — 2026-09-12

### Fixed

- **UI (dashboard):** the "Recent transactions" panel's internal
  scrolling promised in 1.0.1 did not work — the flex chain had no
  definite height (`.app` only has `min-height`), so with content
  taller than the window the panel stretched to its content and the
  whole page scrolled. The dashboard section now has a definite
  height of "window minus chrome" — the feed scrolls inside the panel
  at any window size.

## [1.0.1] — 2026-09-12

### Fixed

- **Cache:** the `ValidateKey` whitelist now allows `:` — Arch epoch
  versions (`nftables-1:1.1.7-3-…`, the epoch colon is part of the
  file name) previously failed with 400 (`InvalidKeyError`), making
  pacman roll back the whole transaction; a raw `:` and its %3A
  encoding resolve to the same cache object. Same bug class as the
  Fedora caret `^` (CI fact #6). Incident 2026-09-12
  (TEST-KHRZ-ARCH).

### Added

- **CI:** Forgejo/GitHub/Codeberg releases now get a body — the
  `[X.Y.Z]` section from CHANGELOG.md is written into the release
  automatically (the body used to be created empty).

### Changed

- **UI (dashboard):** the "Recent transactions" panel now stretches to
  fill the remaining window height — the feed scrolls inside the panel
  (table header pinned) instead of the whole page; when space is tight
  the panel shrinks to a minimum height while keeping internal
  scrolling.
