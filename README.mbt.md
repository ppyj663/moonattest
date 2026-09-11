# MoonAttest

MoonAttest is an offline MoonBit verifier for signed software build evidence.
It parses a DSSE v1 envelope, checks an in-toto Statement v1 carrying SLSA
Provenance v1, verifies Ed25519 signatures, and applies an explicit trust policy
for artifact digest, source repository, builder identity, and trusted key IDs.

The project targets cloud-native and edge workloads that need a small,
reusable security primitive without a network call.

## Quick start

Install MoonBit 0.1.20260904 or newer and Node.js 20 or newer, then run:

```powershell
moon update
moon test --target js
moon test --target wasm-gc
pwsh -File scripts/e2e.ps1
```

Inspect an envelope:

```powershell
moon run cmd/moonattest inspect fixtures/dsse/valid-envelope.json
```

Run the complete disposable demo:

```powershell
pwsh -File scripts/demo.ps1
```

## Library API

The library package is `ppyj663/moonattest/src`:

```moonbit nocheck
///|
import {
  "ppyj663/moonattest/src" @moonattest,
}

///|
let envelope = @moonattest.parse_envelope(input)

///|
let statement = @moonattest.parse_statement(payload)

///|
let provenance = @moonattest.parse_slsa_provenance(statement.unwrap())

///|
let report = @moonattest.verify_envelope(
  envelope.unwrap(),
  policy,
  trusted_keys,
)

///|
/// Select a named subject when a Statement contains multiple artifacts.
let release_policy = policy.with_subject("release.tar")
```

All parsers return `Result` values, accept unknown extension fields, and reject
missing or malformed required fields. `verify_envelope` returns stable
diagnostic codes and never performs network access.

The verifier accepts the in-toto DSSE media type
`application/vnd.in-toto+json`; other payload types are rejected with
`PAYLOAD_TYPE_MISMATCH` before payload decoding.

Policies target the first subject by default. Use `Policy.with_subject(name)`
when a Statement contains multiple subjects; a missing name produces the
`SUBJECT_NOT_FOUND` diagnostic.

## Supported matrix

| Component | JS | Wasm-GC | Native |
| --- | --- | --- | --- |
| Parsing and policy library | yes | yes | not currently shipped |
| `cmd/moonattest` file CLI | yes | no (Node.js adapter) | not currently shipped |

The CLI deliberately uses a JS-only file adapter; the verification core stays
portable and deterministic.

## Security boundary and non-goals

- Trust is explicit: callers provide public keys and policy constraints.
- Verification is fail-closed and offline. No registry, GitHub, Rekor, or OCI
  service is contacted by the library.
- The current implementation supports raw DSSE envelopes and Ed25519 public keys in
  hex. Sigstore Bundle/Fulcio/Rekor integration, OCI pulls, key discovery,
  timestamp freshness, and SLSA level certification are outside the current
  implementation.
- `hustcer/ed25519` is pure MoonBit but not independently audited; see
  `SECURITY.md` before production deployment.

## Project status

Version 0.1.0 provides 19 library tests across JS and Wasm-GC plus a
PowerShell/Node end-to-end tamper demonstration. See `docs/verification.md` for
the reproducible command matrix.

## License

Apache-2.0. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
