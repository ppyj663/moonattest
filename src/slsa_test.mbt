///|
test "extract builder and source from SLSA provenance" {
  let statement = @moonattest.parse_statement(
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"artifact.bin\",\"digest\":{\"sha256\":\"abc123\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"externalParameters\":{\"repository\":{\"url\":\"https://github.com/example/project\"}}},\"runDetails\":{\"builder\":{\"id\":\"https://builder.example/id\"}}}}",
  )
  guard statement is Ok(statement) else { fail("valid statement was rejected") }
  let result = @moonattest.parse_slsa_provenance(statement)
  guard result is Ok(provenance) else { fail("valid provenance was rejected") }
  assert_eq(provenance.builder_id, "https://builder.example/id")
  assert_eq(provenance.source_uri, "https://github.com/example/project")
}

///|
test "reject provenance without a builder id" {
  let statement = @moonattest.parse_statement(
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"artifact.bin\",\"digest\":{\"sha256\":\"abc123\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"externalParameters\":{\"repository\":{\"url\":\"https://github.com/example/project\"}}},\"runDetails\":{\"builder\":{}}}}",
  )
  guard statement is Ok(statement) else {
    fail("test statement was rejected too early")
  }
  let result = @moonattest.parse_slsa_provenance(statement)
  guard result is Err(SlsaMissingField("runDetails.builder.id")) else {
    fail("missing builder id was not diagnosed")
  }
}
