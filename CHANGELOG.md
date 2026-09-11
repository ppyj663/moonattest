# Changelog

## 0.1.0 - 2026-09-11

- Added typed DSSE envelope parsing and exact UTF-8 PAE construction.
- Added in-toto Statement v1 and SLSA Provenance v1 parsing.
- Added SHA-256 and Ed25519 verification against explicit trust policy.
- Added optional subject-name selection for Statements containing multiple artifacts.
- Added strict in-toto DSSE payload-type validation.
- Added configurable minimum trusted-signature thresholds with duplicate-key protection.
- Added JS CLI commands `inspect` and `verify` with exit codes 0/1/2.
- Added disposable signed demo and tamper-focused end-to-end regression.
