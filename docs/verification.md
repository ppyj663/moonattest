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
pwsh -File scripts/coverage.ps1
moon package --list
pwsh -File scripts/e2e.ps1
```

The library package supports JavaScript and Wasm-GC. The file-oriented CLI uses
the JavaScript target because its adapter reads local files through Node.js.

CI pins MoonBit `0.1.20260904` and moonc `v0.10.12+1634b282e`. After the official
installer runs, the workflow checks the exact SHA-256 values of `moon`, `moonc`,
and `moonrun` on Linux and Windows. An upstream change to the moving download
channel therefore fails closed until the version and hashes are reviewed.

The Linux CI job measures branch coverage for `ppyj663/moonattest/src`, enforces
a 70% minimum, adds the per-file summary to the Actions run summary, and uploads
the summary plus Cobertura XML as the `moonattest-coverage` artifact. The CLI
adapter is exercised separately by the end-to-end suite.

The end-to-end script creates temporary signed envelopes and artifacts, verifies
both digest and direct-file inputs plus repeated-`--public-key` multi-signature
cases, and checks deterministic rejection for unreadable or tampered artifacts,
duplicate or malformed key configuration, malformed or mismatched SHA-256
digests, source, builder, signature, and malformed-Base64 changes. Temporary
files are deleted when the script finishes.
