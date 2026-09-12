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
  assert_eq(
    policy.expected_digest,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(report.ok, true)
}
