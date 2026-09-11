///|
test "parse an in-toto statement with a SLSA predicate" {
  let result = @moonattest.parse_statement(
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"artifact.bin\",\"digest\":{\"sha256\":\"abc123\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"externalParameters\":{\"repository\":{\"url\":\"https://github.com/example/project\"}}},\"runDetails\":{\"builder\":{\"id\":\"https://builder.example/id\"}}}}",
  )
  guard result is Ok(statement) else { fail("valid statement was rejected") }
  assert_eq(statement.statement_type, "https://in-toto.io/Statement/v1")
  assert_eq(statement.subjects.length(), 1)
  assert_eq(statement.subjects[0].name, "artifact.bin")
  assert_eq(statement.subjects[0].digest_algorithm, "sha256")
  assert_eq(statement.subjects[0].digest, "abc123")
  assert_eq(statement.predicate_type, "https://slsa.dev/provenance/v1")
}

///|
test "reject a statement with the wrong predicate type" {
  let result = @moonattest.parse_statement(
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"artifact.bin\",\"digest\":{\"sha256\":\"abc123\"}}],\"predicateType\":\"https://example.invalid/predicate\",\"predicate\":{}}",
  )
  guard result is Err(WrongPredicate) else {
    fail("wrong predicate type was not diagnosed")
  }
}

///|
test "reject a statement without subjects" {
  let result = @moonattest.parse_statement(
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{}}",
  )
  guard result is Err(EmptySubjects) else {
    fail("empty subjects were not diagnosed")
  }
}
