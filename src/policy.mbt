///|
fn add_finding(
  findings : Array[Finding],
  code : String,
  message : String,
) -> Unit {
  findings.push(Finding::new(code, message))
}

///|
fn select_subject(statement : Statement, requested_name : String) -> Subject? {
  if requested_name == "" {
    return Some(statement.subjects[0])
  }
  for subject in statement.subjects {
    if subject.name == requested_name {
      return Some(subject)
    }
  }
  None
}

///|
fn check_policy(
  statement : Statement,
  provenance : Provenance,
  policy : Policy,
  findings : Array[Finding],
) -> Unit {
  let subject = match select_subject(statement, policy.subject_name) {
    Some(subject) => subject
    None => {
      add_finding(
        findings, "SUBJECT_NOT_FOUND", "policy subject name does not exist in statement",
      )
      return
    }
  }
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
