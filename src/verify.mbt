///|
fn failed_report(findings : Array[Finding]) -> Report {
  Report::new(false, findings)
}

///|
const INTOTO_PAYLOAD_TYPE : String = "application/vnd.in-toto+json"

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
  if envelope.payload_type != INTOTO_PAYLOAD_TYPE {
    add_finding(
      findings, "PAYLOAD_TYPE_MISMATCH", "DSSE payload type is not application/vnd.in-toto+json",
    )
    return failed_report(findings)
  }
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
  let valid_trusted_key_ids : Array[String] = []
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
      if !valid_trusted_key_ids.contains(signature.key_id) {
        valid_trusted_key_ids.push(signature.key_id)
      }
    } else {
      add_finding(findings, "SIGNATURE_INVALID", "signature did not verify")
    }
  }
  if policy.min_valid_signatures < 1 {
    add_finding(
      findings, "INVALID_SIGNATURE_THRESHOLD", "policy minimum signatures must be at least one",
    )
  }
  if valid_trusted_key_ids.is_empty() {
    add_finding(findings, "NO_VALID_SIGNATURE", "no trusted signature verified")
  } else if valid_trusted_key_ids.length() < policy.min_valid_signatures {
    add_finding(
      findings, "SIGNATURE_THRESHOLD_UNMET", "verified trusted signatures are below policy minimum",
    )
  }
  Report::new(findings.is_empty(), findings)
}
