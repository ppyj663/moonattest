# Security policy

## Scope

MoonAttest is a verification core, not a complete supply-chain platform. It
handles a caller-provided DSSE envelope, in-toto/SLSA JSON, public keys, and a
local policy. It does not fetch keys, resolve repositories, contact Rekor or
Fulcio, pull OCI artifacts, or decide whether a build meets a SLSA level.

## Fail-closed behavior

Malformed JSON/Base64, missing required fields, unsupported predicate types,
unknown key IDs, invalid signatures, and policy mismatches produce a rejected
report. Callers should treat any `ok == false` report as untrusted output.

## Cryptography

Ed25519 verification is provided by the pinned `hustcer/ed25519@0.6.0`
Mooncakes package. SHA-256 is provided by `gmlewis/sha256@0.17.33`. These
dependencies are documented in `THIRD_PARTY_NOTICES.md`; neither dependency is
claimed to be independently audited by this project.

## Reporting a vulnerability

Do not include private keys or unpublished exploit details in a public issue.
Open a private GitHub security advisory for `ppyj663/moonattest`, or contact the
maintainer through the GitHub account `ppyj663`. Reproduction steps and a
minimal fixture are appreciated.
