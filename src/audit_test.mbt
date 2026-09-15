///|
test "render a passing batch as stable JSON" {
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
  assert_eq(
    batch_report_json(report),
    "{\"ok\":true,\"passed\":2,\"failed\":0,\"results\":[" +
    "{\"name\":\"release\",\"ok\":true,\"findings\":[]}," +
    "{\"name\":\"release-copy\",\"ok\":true,\"findings\":[]}]}",
  )
}

///|
test "render failed findings in a readable Markdown audit" {
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
  assert_eq(
    batch_report_markdown(report),
    "# MoonAttest batch audit\n\n" +
    "- Status: **FAILED**\n" +
    "- Passed: 1\n" +
    "- Failed: 1\n\n" +
    "## valid — PASS\n\n" +
    "No findings.\n\n" +
    "## invalid — FAIL\n\n" +
    "- `BUILD_TYPE_MISMATCH`: provenance build type does not match policy\n",
  )
}
