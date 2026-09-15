///|
test "public model constructors preserve verification inputs" {
  let signature = @moonattest.Signature::new("release-key", "c2ln")
  let envelope = @moonattest.Envelope::new(
    "application/vnd.in-toto+json",
    "e30=",
    [signature],
  )
  let subject = @moonattest.Subject::new(
    "artifact.bin", "sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  let provenance = @moonattest.Provenance::new(
    "https://builder.example/id", "https://github.com/example/project", "https://example.com/build/v1",
  )
  let policy = @moonattest.Policy::new(
    "sha256",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "https://github.com/example/project",
    "https://builder.example/id",
    ["release-key"],
  )
  let finding = @moonattest.Finding::new("OK", "verification passed")
  let report = @moonattest.Report::new(true, [finding])
  assert_eq(signature.key_id, "release-key")
  assert_eq(envelope.payload_type, "application/vnd.in-toto+json")
  assert_eq(subject.digest_algorithm, "sha256")
  assert_eq(provenance.builder_id, "https://builder.example/id")
  assert_eq(provenance.build_type, "https://example.com/build/v1")
  assert_eq(policy.build_type, "")
  assert_eq(
    policy.with_build_type("https://example.com/build/v1").build_type,
    "https://example.com/build/v1",
  )
  assert_eq(
    policy.expected_digest,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(report.ok, true)
}

///|
test "replace a policy digest without changing other constraints" {
  let policy = valid_policy()
    .with_build_type("https://example.com/build/v1")
    .with_subject("artifact.bin")
    .with_min_valid_signatures(2)
  let digest = "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34"
  let updated = policy.with_expected_digest(digest)
  assert_eq(updated.expected_digest, digest)
  assert_eq(updated.digest_algorithm, policy.digest_algorithm)
  assert_eq(updated.source_uri, policy.source_uri)
  assert_eq(updated.builder_id, policy.builder_id)
  assert_eq(updated.build_type, policy.build_type)
  assert_eq(updated.subject_name, policy.subject_name)
  assert_eq(updated.min_valid_signatures, policy.min_valid_signatures)
}
