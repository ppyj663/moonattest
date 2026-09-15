# Changelog

## Unreleased

- Added reusable JSON policy documents with strict key, digest, and threshold validation.
- Added versioned batch audit manifests with unique named entries.
- Added `moonattest audit` with text, JSON, and Markdown output.
- Added manifest-relative loading of local artifacts, DSSE envelopes, and policies.
- Added independent policy and runtime SHA-256 constraints so batch verification checks actual files without discarding pinned policy digests.
- Added digest evidence fields to JSON and Markdown audit reports.
- Added passing, policy-rejected, and tampered-artifact audit fixtures and end-to-end coverage.

## 0.1.0 - 2026-09-11

- Added typed DSSE envelope parsing and exact UTF-8 PAE construction.
- Added in-toto Statement v1 and SLSA Provenance v1 parsing.
- Added required SLSA v1 `buildDefinition.buildType` parsing.
- Added optional exact build-type policy enforcement and CLI diagnostics.
- Added fail-closed validation for empty CLI trust constraints.
- Added SHA-256 and Ed25519 verification against explicit trust policy.
- Added optional subject-name selection for Statements containing multiple artifacts.
- Added ambiguity detection for duplicate subject names.
- Added strict in-toto DSSE payload-type validation.
- Added configurable minimum trusted-signature thresholds with duplicate-key protection.
- Added repeatable CLI `--public-key` options for multi-signature verification.
- Added CLI validation for 32-byte hexadecimal Ed25519 public keys.
- Added strict 32-byte hexadecimal validation for SHA-256 subject and policy digests.
- Added direct local artifact verification with built-in SHA-256 calculation.
- Added JS CLI commands `inspect` and `verify` with exit codes 0/1/2.
- Added disposable signed demo and tamper-focused end-to-end regression.
- Added automated, checksum-protected GitHub Releases for matching version tags.
