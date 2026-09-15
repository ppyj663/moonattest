///|
/// Errors returned before a batch starts verification.
pub suberror BatchError {
  BatchEmpty
  BatchEmptyName
  BatchDuplicateName(String)
}

///|
/// One named envelope and the policy document that should be used for it.
pub(all) struct BatchEntry {
  name : String
  envelope : Envelope
  policy_document : PolicyDocument
}

///|
pub fn BatchEntry::new(
  name : String,
  envelope : Envelope,
  policy_document : PolicyDocument,
) -> BatchEntry {
  { name, envelope, policy_document, }
}

///|
/// The verification result for one named batch entry.
pub(all) struct BatchResult {
  name : String
  report : Report
}

///|
pub fn BatchResult::new(name : String, report : Report) -> BatchResult {
  { name, report, }
}

///|
/// Aggregate status for a batch. Individual reports remain available so a
/// caller can explain which entries failed and why.
pub(all) struct BatchReport {
  ok : Bool
  results : Array[BatchResult]
  passed : Int
  failed : Int
}

///|
pub fn BatchReport::new(
  ok : Bool,
  results : Array[BatchResult],
  passed : Int,
  failed : Int,
) -> BatchReport {
  { ok, results, passed, failed, }
}

///|
/// Verify every entry in input order and keep both aggregate and per-entry
/// outcomes. An empty or ambiguously named batch is rejected before any
/// envelope is verified.
pub fn verify_batch(
  entries : Array[BatchEntry],
) -> Result[BatchReport, BatchError] {
  guard !entries.is_empty() else { return Err(BatchEmpty) }
  let names : Array[String] = []
  for entry in entries {
    if entry.name.is_empty() {
      return Err(BatchEmptyName)
    }
    if names.contains(entry.name) {
      return Err(BatchDuplicateName(entry.name))
    }
    names.push(entry.name)
  }
  let results : Array[BatchResult] = []
  let mut passed = 0
  let mut failed = 0
  for entry in entries {
    let report = verify_envelope(
      entry.envelope,
      entry.policy_document.policy,
      entry.policy_document.trusted_keys,
    )
    if report.ok {
      passed += 1
    } else {
      failed += 1
    }
    results.push(BatchResult::new(entry.name, report))
  }
  Ok(BatchReport::new(failed == 0, results, passed, failed))
}
