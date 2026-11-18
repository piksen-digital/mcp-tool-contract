# Security notes

## GHSA-g3hv-75wg-m249 (minimatch, moderate)

Transitive via `apify -> @crawlee/core -> minimatch`. The advisory requires an
attacker-controlled glob pattern to reach `minimatch` preprocessing. This
Actor's input schema does not accept glob patterns; it accepts `targets` with
`type` constrained to a fixed enum and `url` constrained to `format: uri`.
The vulnerable code path is not reachable from `src/main.js`.

Upstream fix is `minimatch@11.0.1`, a breaking major that requires coordinated
`glob@14` overrides. Not applied to avoid destabilizing `@crawlee/core`.
Re-evaluate when `apify` ships a release that bumps `@crawlee/core` to a
`minimatch@11`-compatible line.

`npm audit --omit=dev` reports this as **3 moderate** entries because it counts
each package in the chain (`minimatch`, `@crawlee/core`, `apify`). It is one
advisory (`GHSA-g3hv-75wg-m249`), fixed only in `minimatch@11.0.1+`. The 9.x
line has no fix, and `apify@3.8.0` (the highest version in `^3.4.5`) pins
`@crawlee/core@3.18.2` -> `minimatch@9.0.9`. Forcing `minimatch@11` would
require overriding `glob` to `14.x`, a breaking major with a silent
empty-result failure mode in `@crawlee/core`.

## GHSA-c475-qrg2-pj4r, GHSA-5pm8-86m8-9m6r, GHSA-r4jh-29pc-gfqr (basic-ftp)

Resolved by `overrides.basic-ftp = 6.2.4` in `package.json`. The Actor never
speaks FTP, so these were unreachable, but the override removes them from
`npm audit` so CI stays clean.
