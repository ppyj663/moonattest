///|
test "parse a valid DSSE envelope" {
  let result = @moonattest.parse_envelope(
    "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"e30=\",\"signatures\":[{\"keyid\":\"release-key\",\"sig\":\"c2ln\"}]}",
  )
  guard result is Ok(envelope) else { fail("valid envelope was rejected") }
  assert_eq(envelope.payload_type, "application/vnd.in-toto+json")
  assert_eq(envelope.payload, "e30=")
  assert_eq(envelope.signatures.length(), 1)
  assert_eq(envelope.signatures[0].key_id, "release-key")
}

///|
test "reject missing payload type" {
  let result = @moonattest.parse_envelope(
    "{\"payload\":\"e30=\",\"signatures\":[{\"keyid\":\"k\",\"sig\":\"s\"}]}",
  )
  guard result is Err(MissingField("payloadType")) else {
    fail("missing payloadType was not diagnosed")
  }
}

///|
test "reject an empty signature list" {
  let result = @moonattest.parse_envelope(
    "{\"payloadType\":\"type\",\"payload\":\"eA==\",\"signatures\":[]}",
  )
  guard result is Err(EmptySignatures) else {
    fail("empty signatures were not diagnosed")
  }
}

///|
test "reject malformed base64 in the payload" {
  let result = @moonattest.parse_envelope(
    "{\"payloadType\":\"type\",\"payload\":\"%%%\",\"signatures\":[{\"keyid\":\"k\",\"sig\":\"s\"}]}",
  )
  guard result is Err(InvalidBase64("payload")) else {
    fail("malformed payload base64 was not diagnosed")
  }
}

///|
test "build the DSSE v1 pre-authentication encoding" {
  assert_eq(@moonattest.pae("type", "data"), "DSSEv1 4 type 4 data")
  assert_eq(@moonattest.pae("类型", "x"), "DSSEv1 6 类型 1 x")
}
