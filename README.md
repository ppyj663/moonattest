# MoonAttest

[![CI](https://github.com/ppyj663/moonattest/actions/workflows/ci.yml/badge.svg)](https://github.com/ppyj663/moonattest/actions/workflows/ci.yml)
[![MoonBit](https://img.shields.io/badge/MoonBit-0.1.20260904-f2a900)](https://www.moonbitlang.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Offline verification and release auditing for DSSE-signed, in-toto/SLSA build
provenance, written in MoonBit.

MoonAttest answers a practical release question: **does each local artifact
match build evidence signed by keys I trust and the source, builder, and build
type I expected?** It performs that check deterministically, supports reusable
policy documents and batch audit summaries, and never contacts a registry,
transparency log, key server, or source host.

> MoonAttest 是一个使用 MoonBit 编写的离线软件供应链证明验证器。它验证
> DSSE/Ed25519 签名、in-toto Statement 和 SLSA Provenance，并按照调用方明确
> 提供的制品摘要、源码仓库、构建器、构建类型和可信密钥策略进行失败关闭式校验。

## Why MoonAttest

CI systems can produce signed provenance, but consumers still need a small,
embeddable verifier at the trust boundary. MoonAttest provides that missing
primitive as a portable MoonBit library plus a file-oriented CLI:

- parses DSSE v1 envelopes with strict RFC 4648 Base64 handling;
- constructs the DSSE pre-authentication encoding using UTF-8 byte lengths;
- validates in-toto Statement v1 and SLSA Provenance v1 structures;
- verifies Ed25519 signatures against caller-provided public keys;
- enforces artifact SHA-256, source, builder, build type, and named-subject
  constraints;
- supports distinct-key signature thresholds for multi-signature policies;
- loads reusable JSON policy documents and verifies named batches in input order;
- renders batch results as deterministic JSON or Markdown audit summaries;
- emits stable findings and optional machine-readable JSON;
- remains offline and fail-closed throughout verification.

## One-minute demo

Prerequisites:

- MoonBit `0.1.20260904` or newer;
- Node.js 20 or newer;
- PowerShell 7 (`pwsh`).

From the repository root:

```powershell
moon update
pwsh -File scripts/demo.ps1
```

The disposable demo creates a local artifact and signed envelope, inspects the
envelope, verifies the artifact, and removes the temporary files. Expected
output:

```text
payloadType: application/vnd.in-toto+json
signatures: 1
status: parsed
VERIFIED
```

No private key is stored in the repository. The fixture generator uses an RFC
8032 test seed only for this local demonstration.

## Verify an artifact

MoonAttest hashes the artifact bytes and compares the result with the signed
Statement before applying the remaining policy:

```powershell
moon run cmd/moonattest verify envelope.json `
  --artifact release.tar `
  --source https://github.com/example/project `
  --builder https://builder.example/id `
  --build-type https://example.com/build/v1 `
  --public-key release-key=<32-byte-ed25519-public-key-hex>
```

Use `--digest <sha256-hex>` instead of `--artifact <path>` when a trusted
component has already calculated the digest. Add `--subject <name>` to select a
specific artifact in a multi-subject Statement, `--json` for structured output,
or repeat `--public-key` with `--min-signatures <n>` for a threshold policy.

Inspecting an envelope does not require trust configuration:

```powershell
moon run cmd/moonattest inspect fixtures/dsse/valid-envelope.json
```

The CLI uses exit code `0` for success, `1` for a completed verification that
rejects the evidence, and `2` for invalid input or configuration.

## Reusable policies and batch audits

The library accepts a small JSON policy document so release checks can be
reviewed and reused instead of rebuilt from command-line flags:

```json
{
  "source": "https://github.com/example/project",
  "builder": "https://builder.example/id",
  "expectedDigest": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "buildType": "https://example.com/build/v1",
  "trustedKeys": {
    "release-key": "<32-byte-ed25519-public-key-hex>"
  },
  "minValidSignatures": 1
}
```

`parse_policy_document` validates required fields, key lengths, digests, and
signature thresholds before a verification starts. For a release gate, list
the local artifact, signed envelope, and policy in a versioned audit manifest:

```json
{
  "version": 1,
  "entries": [
    {
      "name": "example-release",
      "artifact": "artifact.txt",
      "envelope": "release-envelope.json",
      "policy": "release-policy.json"
    }
  ]
}
```

Paths are resolved relative to the manifest. MoonAttest hashes every local
artifact, binds the computed digest to its policy, then verifies the signed
provenance:

```powershell
moon run cmd/moonattest audit fixtures/audit/release-manifest.json
moon run cmd/moonattest audit fixtures/audit/release-manifest.json --format json
moon run cmd/moonattest audit fixtures/audit/release-manifest.json --format markdown
```

The command returns `0` when the complete batch passes, `1` when verification
finishes with one or more rejected entries, and `2` for malformed configuration
or unreadable files. Library callers can assemble the same batch directly:

```moonbit nocheck
let policy = @moonattest.parse_policy_document(policy_json).unwrap()
let entries = [
  @moonattest.BatchEntry::new("release", envelope, policy),
]
let audit = @moonattest.verify_batch(entries).unwrap()
let json = @moonattest.batch_report_json(audit)
let markdown = @moonattest.batch_report_markdown(audit)
```

The batch API rejects empty or duplicate names, keeps input order, and reports
both aggregate pass/fail counts and per-entry diagnostic codes. This makes the
same core result usable as a CI gate, a release attachment, or a human review
note.

## Verification flow

```text
local artifact ── SHA-256 ───────────────────────────────┐
                                                        │
DSSE JSON ── envelope + Base64 ── in-toto Statement ── SLSA Provenance
    │                                                   │
    └── PAE + Ed25519 signatures ── explicit policy ────┤
                                                        ▼
                                               Report / findings
```

The `src` package contains pure parsing, hashing, policy, and verification
logic. It performs no file, environment, or network access. The
`cmd/moonattest` package is a thin JavaScript-target adapter for local files,
arguments, output, and process exit codes. See [Architecture](docs/architecture.md)
for the detailed data flow.

## Library API

Import `ppyj663/moonattest/src` and keep trust decisions in the caller:

```moonbit
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
```

Parsers return `Result` values, reject malformed required fields, and tolerate
unknown extension fields. Verification returns stable diagnostic codes rather
than performing hidden key discovery or network fallback.

## Supported targets

| Component | JavaScript | Wasm-GC | Native |
| --- | --- | --- | --- |
| Parsing and policy library | Yes | Yes | Not currently shipped |
| File-oriented CLI | Yes | No (Node.js adapter) | Not currently shipped |

## Reproduce the checks

The public CI workflow runs the same core checks on Ubuntu and Windows. It pins
the MoonBit toolchain version, verifies the SHA-256 of `moon`, `moonc`, and
`moonrun`, enforces a 70% branch-coverage floor, and builds a release package.

```powershell
moon update
moon fmt --check
moon check --target js
moon check --target wasm-gc
moon test --target js
moon test --target wasm-gc
pwsh -File scripts/coverage.ps1 -MinimumPercent 70
moon package --list
pwsh -File scripts/e2e.ps1
```

The suite currently contains 52 library test cases exercised on JavaScript and
Wasm-GC, plus an end-to-end tamper suite for the CLI. Coverage summaries and
Cobertura XML are attached to Linux CI runs. See [Verification](docs/verification.md)
for the reproducible command matrix.

## Scope and ecosystem position

MoonAttest focuses on a standards-based verification boundary rather than a
package manager or an all-in-one supply-chain platform. A registry review found
adjacent MoonBit projects for custom evidence packs, package signing, dependency
policy, and SBOM processing, but no package combining DSSE, in-toto Statement,
SLSA Provenance, and an explicit Ed25519 trust policy. The dated search terms
and comparison are recorded in [Mooncakes overlap analysis](docs/overlap-analysis.md).

Current non-goals include Sigstore Bundle/Fulcio/Rekor integration, OCI pulls,
key discovery, timestamp freshness, and SLSA level certification. Cryptographic
dependencies are pinned but are not claimed to have been independently audited
by this project. Review [Security policy](SECURITY.md) before production use.

## Documentation

- [MoonBit package guide](README.mbt.md)
- [Architecture](docs/architecture.md)
- [Demo notes](docs/demo-script.md)
- [Verification and coverage](docs/verification.md)
- [Release process](docs/releasing.md)
- [Changelog](CHANGELOG.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## License

Licensed under [Apache-2.0](LICENSE).
