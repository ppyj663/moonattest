# MoonAttest

Offline DSSE and SLSA provenance verification in MoonBit.

MoonAttest parses signed in-toto Statements, verifies Ed25519 signatures, and
enforces an explicit trust policy without network access. The detailed guide,
scope, examples, and verification notes are in [README.mbt.md](README.mbt.md).

```powershell
moon update
moon test --target js
pwsh -File scripts/e2e.ps1
```

Repository: <https://github.com/ppyj663/moonattest>
