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
