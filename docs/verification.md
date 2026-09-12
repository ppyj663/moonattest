# Verification

MoonAttest is tested as a portable library and as a JavaScript command-line
adapter. The commands below reproduce the supported build and test matrix from
the repository root.

```powershell
moon update
moon fmt --check
moon check --target js
moon check --target wasm-gc
moon test --target js
moon test --target wasm-gc
moon package --list
pwsh -File scripts/e2e.ps1
```

The library package supports JavaScript and Wasm-GC. The file-oriented CLI uses
the JavaScript target because its adapter reads local files through Node.js.

The end-to-end script creates temporary signed envelopes, verifies both the
single-signature and repeated-`--public-key` multi-signature cases, and checks
deterministic rejection for duplicate or malformed key configuration,
malformed or mismatched SHA-256 digests, source, builder, signature, and
malformed-Base64 changes. Temporary files are deleted when the script finishes.
