///|
test "parse a versioned audit manifest in input order" {
  let text = "{" +
    "\"version\":1," +
    "\"entries\":[" +
    "{\"name\":\"linux\",\"envelope\":\"linux.intoto.jsonl\",\"policy\":\"release-policy.json\"}," +
    "{\"name\":\"wasm\",\"envelope\":\"wasm.intoto.jsonl\",\"policy\":\"release-policy.json\"}" +
    "]}"
  let result = parse_audit_manifest(text.to_string_view())
  guard result is Ok(manifest) else {
    fail("valid audit manifest was rejected")
  }
  assert_eq(manifest.version, 1)
  assert_eq(manifest.entries.length(), 2)
  assert_eq(manifest.entries[0].name, "linux")
  assert_eq(manifest.entries[0].envelope_path, "linux.intoto.jsonl")
  assert_eq(manifest.entries[1].name, "wasm")
  assert_eq(manifest.entries[1].policy_path, "release-policy.json")
}

///|
test "reject an unsupported audit manifest version" {
  let result = parse_audit_manifest(
    "{\"version\":2,\"entries\":[{\"name\":\"release\",\"envelope\":\"a.json\",\"policy\":\"p.json\"}]}".to_string_view(),
  )
  guard result is Err(AuditManifestUnsupportedVersion(2)) else {
    fail("unsupported version was not diagnosed")
  }
}

///|
test "reject a fractional audit manifest version" {
  let result = parse_audit_manifest(
    "{\"version\":1.5,\"entries\":[{\"name\":\"release\",\"envelope\":\"a.json\",\"policy\":\"p.json\"}]}".to_string_view(),
  )
  guard result is Err(AuditManifestInvalidField("version")) else {
    fail("fractional version was not diagnosed")
  }
}

///|
test "reject an empty audit manifest" {
  let result = parse_audit_manifest(
    "{\"version\":1,\"entries\":[]}".to_string_view(),
  )
  guard result is Err(AuditManifestEmptyEntries) else {
    fail("empty audit manifest was not diagnosed")
  }
}

///|
test "reject duplicate audit entry names" {
  let result = parse_audit_manifest(
    ("{\"version\":1,\"entries\":[" +
    "{\"name\":\"release\",\"envelope\":\"a.json\",\"policy\":\"p.json\"}," +
    "{\"name\":\"release\",\"envelope\":\"b.json\",\"policy\":\"p.json\"}" +
    "]}").to_string_view(),
  )
  guard result is Err(AuditManifestDuplicateName("release")) else {
    fail("duplicate entry name was not diagnosed")
  }
}

///|
test "reject an empty audit entry path" {
  let result = parse_audit_manifest(
    "{\"version\":1,\"entries\":[{\"name\":\"release\",\"envelope\":\"\",\"policy\":\"p.json\"}]}".to_string_view(),
  )
  guard result is Err(AuditManifestEmptyEntryField(0, "envelope")) else {
    fail("empty envelope path was not diagnosed")
  }
}
