///|
const INTOTO_STATEMENT_V1 : String = "https://in-toto.io/Statement/v1"

///|
const SLSA_PROVENANCE_V1 : String = "https://slsa.dev/provenance/v1"

///|
/// Errors returned while decoding an in-toto Statement.
pub suberror IntotoError {
  IntotoInvalidJson
  IntotoNotObject
  IntotoWrongType
  WrongPredicate
  IntotoMissingField(String)
  IntotoInvalidField(String)
  EmptySubjects
  MissingDigest(String)
  InvalidDigest(String)
}

///|
fn intoto_required_string(
  object : Map[String, Json],
  field : String,
) -> Result[String, IntotoError] {
  match object.get(field) {
    None => Err(IntotoMissingField(field))
    Some(String(value)) => Ok(value)
    Some(_) => Err(IntotoInvalidField(field))
  }
}

///|
fn parse_subject(value : Json) -> Result[Subject, IntotoError] {
  guard value is Object(object) else {
    return Err(IntotoInvalidField("subject"))
  }
  let name = match intoto_required_string(object, "name") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let digest_value = match object.get("digest") {
    None => return Err(IntotoMissingField("subject.digest"))
    Some(value) => value
  }
  guard digest_value is Object(digest_object) else {
    return Err(IntotoInvalidField("subject.digest"))
  }
  let mut first_digest : (String, String)? = None
  let mut sha256_digest : (String, String)? = None
  for (algorithm, digest_value) in digest_object.iter() {
    guard digest_value is String(digest) else {
      return Err(IntotoInvalidField("subject.digest"))
    }
    guard !digest.is_empty() else { return Err(MissingDigest(algorithm)) }
    if algorithm == "sha256" && !is_valid_sha256_digest(digest) {
      return Err(InvalidDigest(algorithm))
    }
    if first_digest is None {
      first_digest = Some((algorithm, digest))
    }
    if algorithm == "sha256" {
      sha256_digest = Some((algorithm, digest))
    }
  }
  let (digest_algorithm, digest) = match sha256_digest {
    Some(value) => value
    None =>
      match first_digest {
        Some(value) => value
        None => return Err(MissingDigest(name))
      }
  }
  Ok(Subject::new(name, digest_algorithm, digest))
}

///|
/// Parse an in-toto Statement v1 and retain its predicate for a typed parser.
/// Unknown statement and predicate fields are ignored intentionally.
pub fn parse_statement(text : StringView) -> Result[Statement, IntotoError] {
  let document = @json.parse(text) catch { _ => return Err(IntotoInvalidJson) }
  guard document is Object(object) else { return Err(IntotoNotObject) }
  let statement_type = match intoto_required_string(object, "_type") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  guard statement_type == INTOTO_STATEMENT_V1 else {
    return Err(IntotoWrongType)
  }
  let subjects_value = match object.get("subject") {
    None => return Err(IntotoMissingField("subject"))
    Some(value) => value
  }
  guard subjects_value is Array(subject_values) else {
    return Err(IntotoInvalidField("subject"))
  }
  guard !subject_values.is_empty() else { return Err(EmptySubjects) }
  let subjects : Array[Subject] = []
  for value in subject_values {
    let subject = match parse_subject(value) {
      Ok(subject) => subject
      Err(error) => return Err(error)
    }
    subjects.push(subject)
  }
  let predicate_type = match intoto_required_string(object, "predicateType") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  guard predicate_type == SLSA_PROVENANCE_V1 else { return Err(WrongPredicate) }
  let predicate = match object.get("predicate") {
    None => return Err(IntotoMissingField("predicate"))
    Some(value) => value
  }
  guard predicate is Object(_) else {
    return Err(IntotoInvalidField("predicate"))
  }
  Ok(Statement::new(statement_type, subjects, predicate_type, predicate))
}
