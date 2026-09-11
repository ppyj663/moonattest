# Third-party notices

MoonAttest is Apache-2.0. The following pinned Mooncakes dependencies are used
at build time:

| Module | Version | Use | License |
| --- | --- | --- | --- |
| `moonbitlang/core` | bundled with MoonBit 0.1.20260904 | JSON, Base64, UTF-8, hex, environment | Apache-2.0 |
| `gmlewis/sha256` | 0.17.33 | SHA-256 digest | Apache-2.0 |
| `gmlewis/base64` | 0.16.12 (transitive) | dependency support | Apache-2.0 |
| `hustcer/ed25519` | 0.6.0 | Ed25519 verification | Apache-2.0 |
| `moonbitlang/x` | 0.5.1 (transitive) | Ed25519 SHA-512 support | Apache-2.0 |

The exact dependency manifests are resolved by `moon.mod` when the MoonBit
toolchain materializes the local cache. Each upstream package keeps its own
license and attribution in `.mooncakes/` during development.
