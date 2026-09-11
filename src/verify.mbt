///|
fn failed_report(findings : Array[Finding]) -> Report {
  Report::new(false, findings)
}

///|
/// Verify a DSSE envelope, its in-toto/SLSA payload, and an explicit trust policy.
/// Verification is offline and fails closed: any malformed input, policy
/// mismatch, or missing valid trusted signature yields `ok == false`.
pub fn verify_envelope(
  envelope : Envelope,
  policy : Policy,
  trusted_keys : Map[String, String],
) -> Report {
  let findings : Array[Finding] = []
  let payload_bytes = @base64.decode(envelope.payload.to_string_view()) catch {
    _ => {
      add_finding(
        findings, "PAYLOAD_INVALID", "DSSE payload is not valid base64",
      )
      return failed_report(findings)
    }
  }
  let payload = @utf8.decode(payload_bytes) catch {
    _ => {
      add_finding(
        findings, "PAYLOAD_INVALID", "DSSE payload is not valid UTF-8",
      )
      return failed_report(findings)
    }
  }
  let statement = match parse_statement(payload.to_string_view()) {
    Ok(value) => value
    Err(_) => {
      add_finding(
        findings, "STATEMENT_INVALID", "payload is not a valid in-toto statement",
      )
      return failed_report(findings)
    }
  }
  let provenance = match parse_slsa_provenance(statement) {
    Ok(value) => value
    Err(_) => {
      add_finding(
        findings, "PROVENANCE_INVALID", "payload is not valid SLSA provenance",
      )
      return failed_report(findings)
    }
  }
  check_policy(statement, provenance, policy, findings)
  let mut valid_trusted_signatures = 0
  for signature in envelope.signatures {
    if !policy.trusted_key_ids.contains(signature.key_id) {
      add_finding(
        findings, "KEY_UNTRUSTED", "signature key id is not trusted by policy",
      )
      continue
    }
    let public_key_hex = match trusted_keys.get(signature.key_id) {
      Some(value) => value
      None => {
        add_finding(
          findings, "KEY_NOT_FOUND", "trusted key id has no public key material",
        )
        continue
      }
    }
    if verify_signature(envelope, payload, signature, public_key_hex) {
      valid_trusted_signatures += 1
    } else {
      add_finding(findings, "SIGNATURE_INVALID", "signature did not verify")
    }
  }
  if valid_trusted_signatures == 0 {
    add_finding(findings, "NO_VALID_SIGNATURE", "no trusted signature verified")
  }
  Report::new(findings.is_empty(), findings)
}
