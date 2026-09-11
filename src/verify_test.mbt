///|
let test_payload : String = "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"artifact.bin\",\"digest\":{\"sha256\":\"abc123\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"externalParameters\":{\"repository\":{\"url\":\"https://github.com/example/project\"}}},\"runDetails\":{\"builder\":{\"id\":\"https://builder.example/id\"}}}}"

///|
let two_subject_payload : String = "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"source.tar\",\"digest\":{\"sha256\":\"abc123\"}},{\"name\":\"release.tar\",\"digest\":{\"sha256\":\"def456\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"externalParameters\":{\"repository\":{\"url\":\"https://github.com/example/project\"}}},\"runDetails\":{\"builder\":{\"id\":\"https://builder.example/id\"}}}}"

///|
let test_seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"

///|
let second_test_seed : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
let test_public_key : String = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

///|
fn envelope_for_payload(payload : String) -> Envelope {
  let pae_bytes = @utf8.encode(
    pae("application/vnd.in-toto+json", payload).to_string_view(),
  )
  let signature_bytes = @ed25519.sign(test_seed, pae_bytes) catch {
    _ => panic()
  }
  let signature = @base64.encode(signature_bytes)
  Envelope::new(
    "application/vnd.in-toto+json",
    @base64.encode(@utf8.encode(payload.to_string_view())),
    [Signature::new("release-key", signature)],
  )
}

///|
fn envelope_with_two_signatures() -> Envelope {
  let pae_bytes = @utf8.encode(
    pae("application/vnd.in-toto+json", test_payload).to_string_view(),
  )
  let first = @base64.encode(
    @ed25519.sign(test_seed, pae_bytes) catch {
      _ => panic()
    },
  )
  let second = @base64.encode(
    @ed25519.sign(second_test_seed, pae_bytes) catch {
      _ => panic()
    },
  )
  Envelope::new(
    "application/vnd.in-toto+json",
    @base64.encode(@utf8.encode(test_payload.to_string_view())),
    [Signature::new("release-key", first), Signature::new("backup-key", second)],
  )
}

///|
fn valid_envelope() -> Envelope {
  envelope_for_payload(test_payload)
}

///|
fn valid_policy() -> Policy {
  Policy::new(
    "sha256",
    "abc123",
    "https://github.com/example/project",
    "https://builder.example/id",
    ["release-key"],
  )
}

///|
fn valid_keys() -> Map[String, String] {
  Map([("release-key", test_public_key)])
}

///|
fn two_valid_keys() -> Map[String, String] {
  let second_public_key = @ed25519.derive_public_key(second_test_seed) catch {
    _ => panic()
  }
  Map([
    ("release-key", test_public_key),
    ("backup-key", @hex.encode(second_public_key)),
  ])
}

///|
fn report_has_code(report : Report, code : String) -> Bool {
  for finding in report.findings {
    if finding.code == code {
      return true
    }
  }
  false
}

///|
test "verify a signed provenance envelope" {
  let report = verify_envelope(valid_envelope(), valid_policy(), valid_keys())
  assert_eq(report.ok, true)
  assert_eq(report.findings.length(), 0)
}

///|
test "reject an invalid signature" {
  let envelope = Envelope::new(
    "application/vnd.in-toto+json",
    @base64.encode(@utf8.encode(test_payload.to_string_view())),
    [Signature::new("release-key", "AAAA")],
  )
  let report = verify_envelope(envelope, valid_policy(), valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "SIGNATURE_INVALID"), true)
}

///|
test "reject a source mismatch" {
  let policy = Policy::new(
    "sha256",
    "abc123",
    "https://github.com/other/project",
    "https://builder.example/id",
    ["release-key"],
  )
  let report = verify_envelope(valid_envelope(), policy, valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "SOURCE_MISMATCH"), true)
}

///|
test "reject a builder mismatch" {
  let policy = Policy::new(
    "sha256",
    "abc123",
    "https://github.com/example/project",
    "https://builder.example/other",
    ["release-key"],
  )
  let report = verify_envelope(valid_envelope(), policy, valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "BUILDER_MISMATCH"), true)
}

///|
test "reject an artifact digest mismatch" {
  let policy = Policy::new(
    "sha256",
    "deadbeef",
    "https://github.com/example/project",
    "https://builder.example/id",
    ["release-key"],
  )
  let report = verify_envelope(valid_envelope(), policy, valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "DIGEST_MISMATCH"), true)
}

///|
test "reject a signature made by an untrusted key id" {
  let envelope = Envelope::new(
    "application/vnd.in-toto+json",
    @base64.encode(@utf8.encode(test_payload.to_string_view())),
    [Signature::new("unknown-key", "AAAA")],
  )
  let report = verify_envelope(envelope, valid_policy(), valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "KEY_UNTRUSTED"), true)
}

///|
test "verify a named subject instead of the first subject" {
  let policy = valid_policy().with_subject("release.tar")
  let policy = { ..policy, expected_digest: "def456", }
  let report = verify_envelope(
    envelope_for_payload(two_subject_payload),
    policy,
    valid_keys(),
  )
  assert_eq(report.ok, true)
  assert_eq(report.findings.length(), 0)
}

///|
test "reject a policy subject name that is absent" {
  let policy = valid_policy().with_subject("missing.tar")
  let report = verify_envelope(
    envelope_for_payload(two_subject_payload),
    policy,
    valid_keys(),
  )
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "SUBJECT_NOT_FOUND"), true)
}

///|
test "reject a non-in-toto DSSE payload type" {
  let envelope = Envelope::new(
    "application/octet-stream",
    @base64.encode(@utf8.encode(test_payload.to_string_view())),
    [],
  )
  let report = verify_envelope(envelope, valid_policy(), valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report.findings.length(), 1)
  assert_eq(report_has_code(report, "PAYLOAD_TYPE_MISMATCH"), true)
}

///|
test "require distinct trusted signatures when policy sets a threshold" {
  let policy = Policy::new(
    "sha256",
    "abc123",
    "https://github.com/example/project",
    "https://builder.example/id",
    ["release-key", "backup-key"],
  ).with_min_valid_signatures(2)
  let report = verify_envelope(
    envelope_with_two_signatures(),
    policy,
    two_valid_keys(),
  )
  assert_eq(report.ok, true)
  assert_eq(report.findings.length(), 0)
}

///|
test "do not count duplicate signatures toward a threshold" {
  let envelope = valid_envelope()
  let signature = envelope.signatures[0].sig.to_string_view()
  let duplicate = Envelope::new(envelope.payload_type, envelope.payload, [
    Signature::new("release-key", signature.to_owned()),
    Signature::new("release-key", signature.to_owned()),
  ])
  let policy = valid_policy().with_min_valid_signatures(2)
  let report = verify_envelope(duplicate, policy, valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "SIGNATURE_THRESHOLD_UNMET"), true)
}

///|
test "reject a non-positive signature threshold" {
  let policy = valid_policy().with_min_valid_signatures(0)
  let report = verify_envelope(valid_envelope(), policy, valid_keys())
  assert_eq(report.ok, false)
  assert_eq(report_has_code(report, "INVALID_SIGNATURE_THRESHOLD"), true)
}
