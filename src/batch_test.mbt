///|
fn batch_policy_document() -> PolicyDocument {
  PolicyDocument::new(valid_policy(), valid_keys())
}

///|
test "verify a non-empty batch in input order" {
  let first = BatchEntry::new(
    "release",
    valid_envelope(),
    batch_policy_document(),
  )
  let second = BatchEntry::new(
    "release-copy",
    valid_envelope(),
    batch_policy_document(),
  )
  let result = verify_batch([first, second])
  guard result is Ok(report) else { fail("valid batch was rejected") }
  assert_eq(report.ok, true)
  assert_eq(report.results.length(), 2)
  assert_eq(report.passed, 2)
  assert_eq(report.failed, 0)
  assert_eq(report.results[0].name, "release")
  assert_eq(report.results[1].name, "release-copy")
}

///|
test "retain failed entries in the batch summary" {
  let valid = BatchEntry::new(
    "valid",
    valid_envelope(),
    batch_policy_document(),
  )
  let invalid_policy = valid_policy().with_build_type(
    "https://example.com/build/other",
  )
  let invalid = BatchEntry::new(
    "invalid",
    valid_envelope(),
    PolicyDocument::new(invalid_policy, valid_keys()),
  )
  let result = verify_batch([valid, invalid])
  guard result is Ok(report) else { fail("mixed batch was rejected") }
  assert_eq(report.ok, false)
  assert_eq(report.passed, 1)
  assert_eq(report.failed, 1)
  assert_eq(report.results[1].report.ok, false)
}

///|
test "reject an empty batch" {
  let result = verify_batch([])
  guard result is Err(BatchEmpty) else { fail("empty batch was not diagnosed") }
}

///|
test "reject duplicate batch entry names" {
  let first = BatchEntry::new(
    "release",
    valid_envelope(),
    batch_policy_document(),
  )
  let second = BatchEntry::new(
    "release",
    valid_envelope(),
    batch_policy_document(),
  )
  let result = verify_batch([first, second])
  guard result is Err(BatchDuplicateName("release")) else {
    fail("duplicate batch name was not diagnosed")
  }
}

///|
test "reject an empty batch entry name" {
  let entry = BatchEntry::new("", valid_envelope(), batch_policy_document())
  let result = verify_batch([entry])
  guard result is Err(BatchEmptyName) else {
    fail("empty batch name was not diagnosed")
  }
}
