# Local demonstration

Run `pwsh -File scripts/demo.ps1` to generate a disposable signed envelope and
artifact, inspect the DSSE metadata, and verify the artifact bytes against an
explicit local policy.

Run `pwsh -File scripts/e2e.ps1` to exercise valid verification, policy
mismatches, signature tampering, and malformed Base64. The script asserts the
CLI exit codes and deletes temporary files when it finishes.

The verifier does not contact a registry or key server; the public key and
policy are supplied explicitly.

The demo seed is an RFC 8032 test seed and is used only to create a disposable
temporary file. It is never placed in the repository or accepted by the
verifier as a trust source.
