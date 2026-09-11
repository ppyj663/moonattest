# Five-minute demo script

1. Run `pwsh -File scripts/demo.ps1`.
2. Point out `payloadType` and the one DSSE signature from `inspect`.
3. Point out `VERIFIED` and exit code 0 for the signed envelope.
4. Run `pwsh -File scripts/e2e.ps1` to show the four policy/tamper rejections.
5. Explain that the verifier did not contact a registry or key server; the
   public key and policy were supplied explicitly.

The demo seed is an RFC 8032 test seed and is used only to create a disposable
temporary file. It is never committed or accepted by the verifier as a trust
source.
