///|
fn add_finding(
  findings : Array[Finding],
  code : String,
  message : String,
) -> Unit {
  findings.push(Finding::new(code, message))
}

///|
fn check_policy(
  statement : Statement,
  provenance : Provenance,
  policy : Policy,
  findings : Array[Finding],
) -> Unit {
  let subject = statement.subjects[0]
  if policy.digest_algorithm != "" &&
    subject.digest_algorithm != policy.digest_algorithm {
    add_finding(
      findings, "DIGEST_ALGORITHM_MISMATCH", "subject digest algorithm does not match policy",
    )
  }
  if policy.expected_digest != "" &&
    subject.digest.to_lower() != policy.expected_digest.to_lower() {
    add_finding(
      findings, "DIGEST_MISMATCH", "subject digest does not match policy",
    )
  }
  if policy.source_uri != "" && provenance.source_uri != policy.source_uri {
    add_finding(
      findings, "SOURCE_MISMATCH", "provenance source does not match policy",
    )
  }
  if policy.builder_id != "" && provenance.builder_id != policy.builder_id {
    add_finding(
      findings, "BUILDER_MISMATCH", "provenance builder does not match policy",
    )
  }
}
