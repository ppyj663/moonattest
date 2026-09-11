///|
let test_payload : String = "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"artifact.bin\",\"digest\":{\"sha256\":\"abc123\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"externalParameters\":{\"repository\":{\"url\":\"https://github.com/example/project\"}}},\"runDetails\":{\"builder\":{\"id\":\"https://builder.example/id\"}}}}"

///|
let test_seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"

///|
let test_public_key : String = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

///|
fn valid_envelope() -> Envelope {
  let pae_bytes = @utf8.encode(
    pae("application/vnd.in-toto+json", test_payload).to_string_view(),
  )
  let signature_bytes = @ed25519.sign(test_seed, pae_bytes) catch {
    _ => panic()
  }
  let signature = @base64.encode(signature_bytes)
  Envelope::new(
    "application/vnd.in-toto+json",
    @base64.encode(@utf8.encode(test_payload.to_string_view())),
    [Signature::new("release-key", signature)],
  )
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
