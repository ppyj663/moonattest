///|
let policy_document_json : String = "{" +
  "\"digestAlgorithm\":\"sha256\"," +
  "\"expectedDigest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"," +
  "\"source\":\"https://github.com/example/project\"," +
  "\"builder\":\"https://builder.example/id\"," +
  "\"buildType\":\"https://example.com/build/v1\"," +
  "\"subject\":\"release.tar\"," +
  "\"minValidSignatures\":2," +
  "\"trustedKeys\":{\"release-key\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\"}" +
  "}"

///|
let policy_public_key : String = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

///|
test "parse a reusable policy document" {
  let result = @moonattest.parse_policy_document(policy_document_json)
  guard result is Ok(document) else {
    fail("valid policy document was rejected")
  }
  assert_eq(document.policy.digest_algorithm, "sha256")
  assert_eq(
    document.policy.expected_digest,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(document.policy.source_uri, "https://github.com/example/project")
  assert_eq(document.policy.builder_id, "https://builder.example/id")
  assert_eq(document.policy.build_type, "https://example.com/build/v1")
  assert_eq(document.policy.subject_name, "release.tar")
  assert_eq(document.policy.min_valid_signatures, 2)
  assert_eq(document.trusted_keys.get("release-key"), Some(policy_public_key))
}

///|
test "apply policy document defaults" {
  let result = @moonattest.parse_policy_document(
    "{\"source\":\"s\",\"builder\":\"b\",\"trustedKeys\":{\"k\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\"}}",
  )
  guard result is Ok(document) else { fail("policy defaults were rejected") }
  assert_eq(document.policy.digest_algorithm, "sha256")
  assert_eq(document.policy.min_valid_signatures, 1)
  assert_eq(document.policy.expected_digest, "")
}

///|
test "reject a policy document without a source" {
  let result = @moonattest.parse_policy_document(
    "{\"builder\":\"b\",\"trustedKeys\":{\"k\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\"}}",
  )
  guard result is Err(PolicyMissingField("source")) else {
    fail("missing source was not diagnosed")
  }
}

///|
test "reject an invalid policy public key" {
  let result = @moonattest.parse_policy_document(
    "{\"source\":\"s\",\"builder\":\"b\",\"trustedKeys\":{\"k\":\"abcd\"}}",
  )
  guard result is Err(PolicyInvalidKey("k")) else {
    fail("invalid public key was not diagnosed")
  }
}

///|
test "reject a non-integral signature threshold" {
  let result = @moonattest.parse_policy_document(
    "{\"source\":\"s\",\"builder\":\"b\",\"minValidSignatures\":1.5,\"trustedKeys\":{\"k\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\"}}",
  )
  guard result is Err(PolicyInvalidThreshold) else {
    fail("non-integral threshold was not diagnosed")
  }
}

///|
test "reject an empty trusted key set" {
  let result = @moonattest.parse_policy_document(
    "{\"source\":\"s\",\"builder\":\"b\",\"trustedKeys\":{}}",
  )
  guard result is Err(PolicyEmptyTrustedKeys) else {
    fail("empty trusted keys were not diagnosed")
  }
}
