# Architecture

```text
DSSE JSON -> envelope parser -> payload Base64/UTF-8
                              |
                              v
                  in-toto Statement parser
                              |
                              v
                 SLSA Provenance field reader
                              |
                              v
                policy + Ed25519 verification -> Report
```

The `src` package contains only pure data transformations and verification. It
does not read files, inspect the environment, or make network requests. The
`cmd/moonattest` package is a JS-only adapter that reads a local file, parses a
small set of flags, prints diagnostics, and sets the process exit code.

## Data flow

1. `parse_envelope` checks required DSSE fields, every signature object, and
   strict RFC 4648 Base64.
2. `pae` constructs `DSSEv1 <byte-len> <type> <byte-len> <payload>` using UTF-8
   byte lengths, not MoonBit UTF-16 code-unit lengths.
3. `parse_statement` checks the in-toto v1 type, non-empty subjects, digest
   fields, SLSA predicate type, and retains the predicate object.
4. `parse_slsa_provenance` extracts `runDetails.builder.id` and either
   `buildDefinition.externalParameters.repository.url` or `.source.uri`.
5. `verify_envelope` applies policy checks and verifies each trusted signature.
   A report is successful only when there are no findings and at least one
   trusted signature verifies.

## Extension policy

Unknown JSON fields are ignored at each layer so producers may add fields. The
required version and identity fields are exact-match checks. Adding a new
predicate or signature algorithm requires a new parser/verification path and a
new test fixture; it is not silently inferred from an unknown value.
