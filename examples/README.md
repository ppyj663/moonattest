# MoonAttest examples

Run the five-minute demonstration from the repository root:

```powershell
pwsh -File scripts/demo.ps1
```

The end-to-end regression script exercises the same flow and asserts exit
codes for valid verification, policy mismatches, signature tampering, and
malformed Base64:

```powershell
pwsh -File scripts/e2e.ps1
```

The demo uses a fixed RFC 8032 Ed25519 seed only to create disposable local
fixtures. It never writes private key material to the repository.
