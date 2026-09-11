# Mooncakes overlap analysis

Checked the live Mooncakes registry on 2026-09-11 for `slsa`, `slsa
provenance`, `in-toto`, `dsse`, `sigstore`, and `cosign`. No package exposed a
DSSE + in-toto Statement + SLSA Provenance verifier with an explicit Ed25519
trust policy.

Adjacent projects were intentionally not duplicated:

- `starlittle/MoonEvidence` verifies custom evidence packs, Merkle roots, and
  version chains, not DSSE/SLSA provenance.
- `chenzehaoo/moon_guard` focuses on MoonBit package signing, manifests,
  typosquat detection, and package audit workflows.
- SBOM/license/dependency packages cover inventory and policy, not signed
  in-toto build attestations.

MoonAttest therefore targets the missing interoperability boundary: a small,
offline, reusable verifier for standard cloud-native build evidence. It can
consume artifacts produced by existing CI systems without owning a registry,
key-discovery service, or package manager.
