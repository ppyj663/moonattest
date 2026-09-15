///|
/// Errors returned while loading a reusable verification policy document.
pub suberror PolicyDocumentError {
  PolicyInvalidJson
  PolicyNotObject
  PolicyMissingField(String)
  PolicyInvalidField(String)
  PolicyEmptyField(String)
  PolicyInvalidDigest
  PolicyInvalidKey(String)
  PolicyEmptyTrustedKeys
  PolicyInvalidThreshold
}

///|
/// A policy plus the key material required to evaluate its trusted signatures.
pub(all) struct PolicyDocument {
  policy : Policy
  trusted_keys : Map[String, String]
}

///|
pub fn PolicyDocument::new(
  policy : Policy,
  trusted_keys : Map[String, String],
) -> PolicyDocument {
  { policy, trusted_keys, }
}

///|
fn policy_required_string(
  object : Map[String, Json],
  field : String,
) -> Result[String, PolicyDocumentError] {
  match object.get(field) {
    None => Err(PolicyMissingField(field))
    Some(String(value)) =>
      if value.is_empty() {
        Err(PolicyEmptyField(field))
      } else {
        Ok(value)
      }
    Some(_) => Err(PolicyInvalidField(field))
  }
}

///|
fn policy_optional_string(
  object : Map[String, Json],
  field : String,
  default : String,
) -> Result[String, PolicyDocumentError] {
  match object.get(field) {
    None => Ok(default)
    Some(String(value)) =>
      if value.is_empty() {
        Err(PolicyEmptyField(field))
      } else {
        Ok(value)
      }
    Some(_) => Err(PolicyInvalidField(field))
  }
}

///|
fn policy_threshold(value : Json) -> Result[Int, PolicyDocumentError] {
  match value {
    Number(number, ..) => {
      if number.is_nan() || number.is_pos_inf() || number.is_neg_inf() {
        return Err(PolicyInvalidThreshold)
      }
      let integer = number.to_int()
      if integer < 1 || integer.to_double() != number {
        Err(PolicyInvalidThreshold)
      } else {
        Ok(integer)
      }
    }
    _ => Err(PolicyInvalidThreshold)
  }
}

///|
fn policy_public_key(
  value : Json,
  key_id : String,
) -> Result[String, PolicyDocumentError] {
  guard value is String(public_key) else {
    return Err(PolicyInvalidKey(key_id))
  }
  let decoded = @hex.decode(public_key.to_string_view()) catch {
    _ => return Err(PolicyInvalidKey(key_id))
  }
  if decoded.length() != 32 {
    Err(PolicyInvalidKey(key_id))
  } else {
    Ok(public_key)
  }
}

///|
fn policy_trusted_keys(
  value : Json,
) -> Result[(Array[String], Map[String, String]), PolicyDocumentError] {
  guard value is Object(object) else {
    return Err(PolicyInvalidField("trustedKeys"))
  }
  guard !object.is_empty() else { return Err(PolicyEmptyTrustedKeys) }
  let ids : Array[String] = []
  let pairs : Array[(String, String)] = []
  for (key_id, value) in object.iter() {
    if key_id.is_empty() {
      return Err(PolicyInvalidKey(key_id))
    }
    let public_key = match policy_public_key(value, key_id) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    ids.push(key_id)
    pairs.push((key_id, public_key))
  }
  Ok((ids, Map(pairs)))
}

///|
/// Parse a JSON policy document. Required fields are `source`, `builder`, and
/// `trustedKeys`; optional constraints default to the library defaults.
/// Unknown fields are ignored for forward compatibility.
pub fn parse_policy_document(
  text : StringView,
) -> Result[PolicyDocument, PolicyDocumentError] {
  let document = @json.parse(text) catch { _ => return Err(PolicyInvalidJson) }
  guard document is Object(object) else { return Err(PolicyNotObject) }
  let source_uri = match policy_required_string(object, "source") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let builder_id = match policy_required_string(object, "builder") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let digest_algorithm = match
    policy_optional_string(object, "digestAlgorithm", "sha256") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let expected_digest = match
    policy_optional_string(object, "expectedDigest", "") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if digest_algorithm == "sha256" &&
    expected_digest != "" &&
    !is_valid_sha256_digest(expected_digest) {
    return Err(PolicyInvalidDigest)
  }
  let build_type = match policy_optional_string(object, "buildType", "") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let subject_name = match policy_optional_string(object, "subject", "") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let minimum = match object.get("minValidSignatures") {
    None => 1
    Some(value) =>
      match policy_threshold(value) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
  }
  let (trusted_key_ids, trusted_keys) = match object.get("trustedKeys") {
    None => return Err(PolicyMissingField("trustedKeys"))
    Some(value) =>
      match policy_trusted_keys(value) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
  }
  let policy = Policy::new(
      digest_algorithm, expected_digest, source_uri, builder_id, trusted_key_ids,
    )
    .with_build_type(build_type)
    .with_subject(subject_name)
    .with_min_valid_signatures(minimum)
  Ok(PolicyDocument::new(policy, trusted_keys))
}
