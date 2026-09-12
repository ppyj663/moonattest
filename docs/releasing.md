# Releasing MoonAttest

GitHub Releases are created from version tags. Before tagging, update the
`version` field in `moon.mod` and ensure the main CI workflow succeeds.

Create and push the matching tag:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

The Release workflow independently checks formatting, JS and Wasm-GC builds and
tests, and the end-to-end CLI suite. It then runs `moon package --frozen`, writes
a `SHA256SUMS` file, and creates a GitHub Release containing both files. A tag
that does not exactly match the `moon.mod` version is rejected before release.

The regular CI workflow also builds the current release package on Linux so the
packaging path is continuously tested without publishing anything.
