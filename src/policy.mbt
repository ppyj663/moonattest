///|
fn add_finding(
  findings : Array[Finding],
  code : String,
  message : String,
) -> Unit {
  findings.push(Finding::new(code, message))
}

///|
fn select_subject(
  statement : Statement,
  requested_name : String,
) -> (Subject?, Bool) {
  if requested_name == "" {
    return (Some(statement.subjects[0]), false)
  }
  let mut match_count = 0
  let mut selected : Subject? = None
  for subject in statement.subjects {
    if subject.name == requested_name {
      match_count += 1
      if match_count > 1 {
        return (None, true)
      }
      selected = Some(subject)
    }
  }
  (selected, false)
}

///|
fn check_policy(
  statement : Statement,
  provenance : Provenance,
  policy : Policy,
  findings : Array[Finding],
) -> Unit {
  let (selected_subject, ambiguous) = select_subject(
    statement,
    policy.subject_name,
  )
  if ambiguous {
    add_finding(
      findings, "SUBJECT_AMBIGUOUS", "policy subject name matches more than one statement subject",
    )
    return
  }
  let subject = match selected_subject {
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
  if policy.expected_digest != "" {
    if policy.digest_algorithm == "sha256" &&
      !is_valid_sha256_digest(policy.expected_digest) {
      add_finding(
        findings, "INVALID_POLICY_DIGEST", "policy SHA-256 digest is not 32-byte hexadecimal",
      )
    } else if subject.digest.to_lower() != policy.expected_digest.to_lower() {
      add_finding(
        findings, "DIGEST_MISMATCH", "subject digest does not match policy",
      )
    }
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
  if policy.build_type != "" && provenance.build_type != policy.build_type {
    add_finding(
      findings, "BUILD_TYPE_MISMATCH", "provenance build type does not match policy",
    )
  }
}
