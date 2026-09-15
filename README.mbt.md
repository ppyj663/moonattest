# MoonAttest

MoonAttest is an offline MoonBit verifier and release-audit library for signed
software build evidence. It parses a DSSE v1 envelope, checks an in-toto
Statement v1 carrying SLSA Provenance v1, verifies Ed25519 signatures, and
applies an explicit trust policy for artifact digest, source repository,
builder identity, and trusted key IDs.

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

Verify a local artifact directly. MoonAttest reads the file as bytes and checks
its SHA-256 digest against the signed Statement:

```powershell
moon run cmd/moonattest verify envelope.json `
  --artifact release.tar `
  --source https://github.com/example/project `
  --builder https://builder.example/id `
  --build-type https://example.com/build/v1 `
  --public-key release-key=<release-public-key-hex>
```

Use exactly one of `--artifact <path>` or `--digest <hex>`. The latter remains
available when another trusted component already calculated the digest.

For a policy that requires signatures from two different trusted keys, repeat
`--public-key` and set the threshold explicitly:

```powershell
moon run cmd/moonattest verify envelope.json `
  --digest ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad `
  --source https://github.com/example/project `
  --builder https://builder.example/id `
  --public-key release-key=<release-public-key-hex> `
  --public-key backup-key=<backup-public-key-hex> `
  --min-signatures 2
```

Each public key value must be a 32-byte Ed25519 public key encoded as hex.
Malformed key configuration exits with code `2` before verification starts.
When supplied, the `--digest` value must likewise be a complete 32-byte SHA-256
digest in hexadecimal form. CLI trust constraints reject explicit empty values
instead of silently disabling verification checks.

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

Reusable policy documents and batch audit summaries are available from the same
package:

```moonbit nocheck
///|
let policy_document = @moonattest.parse_policy_document(policy_json).unwrap()

///|
let audit = @moonattest.verify_batch([
  @moonattest.BatchEntry::new("release", envelope.unwrap(), policy_document),
]).unwrap()

///|
let audit_json = @moonattest.batch_report_json(audit)

///|
let audit_markdown = @moonattest.batch_report_markdown(audit)
```

The policy JSON requires `source`, `builder`, and a non-empty `trustedKeys`
object. Optional `expectedDigest`, `buildType`, `subject`, and
`minValidSignatures` fields map directly to the `Policy` constraints. Batch
verification preserves input order, rejects duplicate names, and retains each
entry's findings for CI or release review.

The file-oriented CLI accepts a versioned audit manifest whose entries contain
`name`, `artifact`, `envelope`, and `policy` paths. Paths are relative to the
manifest file. The CLI calculates each local artifact's SHA-256 digest and
keeps it separate from the policy's optional `expectedDigest` before
verification. Audit JSON and Markdown retain both values when available:

```powershell
moon run cmd/moonattest audit fixtures/audit/release-manifest.json --format markdown
```

All parsers return `Result` values, accept unknown extension fields, and reject
missing or malformed required fields. `verify_envelope` returns stable
diagnostic codes and never performs network access.

The verifier accepts the in-toto DSSE media type
`application/vnd.in-toto+json`; other payload types are rejected with
`PAYLOAD_TYPE_MISMATCH` before payload decoding.

Policies target the first subject by default. Use `Policy.with_subject(name)`
when a Statement contains multiple subjects; a missing name produces the
`SUBJECT_NOT_FOUND` diagnostic. Duplicate names are rejected with
`SUBJECT_AMBIGUOUS` instead of selecting one arbitrarily.

Policies require one valid trusted signature by default. Use
`Policy.with_min_valid_signatures(n)` to require signatures from at least `n`
distinct trusted key IDs; duplicate signatures from one key do not increase the
count.

SLSA v1 `buildDefinition.buildType` is required during parsing. Use
`Policy.with_build_type(uri)` or CLI `--build-type <uri>` when the verifier must
also enforce the exact build template; omitting the policy option preserves
compatibility while still requiring the field to exist.

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

The current project provides 52 library tests across JS and Wasm-GC plus a
PowerShell/Node end-to-end tamper demonstration. See `docs/verification.md` for
the reproducible command matrix.

Version tags are published as checksum-protected GitHub Release assets. See
`docs/releasing.md` for the public release procedure.

## License

Apache-2.0. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
