# Vendored fork of node-forge

Fork of [digitalbazaar/forge](https://github.com/digitalbazaar/forge) used as a git submodule / npm workspace
(`vendor/node-forge`) so `npm audit` is clean while upstream has no patched release.

| | |
|---|---|
| Base | 1.4.0 (upstream tag `v1.4.0`) |
| Fork version | 1.4.1 |
| Advisory | [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv) — RSA PKCS#1 v1.5 verify accepts extra DigestAlgorithm elements (signature forgery with low-exponent keys) |
| Change | `lib/rsa.js`: require the DigestAlgorithm sequence to hold 1–2 elements (OID + optional NULL) |
| Tests | `test-vendored/` (`npm test`). The exploit test fails on stock 1.4.0 and passes here; the other 4 pass on both. |
| Upstream suite | Per-file mocha runs of `tests/unit/*.js` and `tests/security/*.js`: 821 passing / 7 failing on **both** stock and the fork (the 7 are pre-existing, unrelated to this change). Upstream's aggregate `tests/unit/index.js` runner stops after the jsbn tests under current Node, so run files individually. |
| `package.json` | devDependencies, upstream scripts and browser bundles (`dist/`, `flash/`) dropped from `files`; `lib/*.js` only |

Upstream fix PR to watch: digitalbazaar/forge #1152.

## Retire this fork when
upstream publishes a release > 1.4.0 that fixes the advisory (`npm view node-forge version`). Then drop the
submodule, remove it from the consumer's `workspaces`, delete the lock entry, `npm install`, confirm `npm audit` is 0.
