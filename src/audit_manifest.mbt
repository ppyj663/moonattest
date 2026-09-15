///|
/// Errors returned while parsing a versioned batch audit manifest.
pub suberror AuditManifestError {
  AuditManifestInvalidJson
  AuditManifestNotObject
  AuditManifestMissingField(String)
  AuditManifestInvalidField(String)
  AuditManifestUnsupportedVersion(Int)
  AuditManifestEmptyEntries
  AuditManifestInvalidEntry(Int)
  AuditManifestMissingEntryField(Int, String)
  AuditManifestInvalidEntryField(Int, String)
  AuditManifestEmptyEntryField(Int, String)
  AuditManifestDuplicateName(String)
}

///|
/// File references for one release artifact. Paths are resolved by the CLI
/// relative to the manifest file; the pure library retains them unchanged.
pub(all) struct AuditManifestEntry {
  name : String
  artifact_path : String
  envelope_path : String
  policy_path : String
}

///|
pub fn AuditManifestEntry::new(
  name : String,
  artifact_path : String,
  envelope_path : String,
  policy_path : String,
) -> AuditManifestEntry {
  { name, artifact_path, envelope_path, policy_path, }
}

///|
/// A versioned collection of release artifacts to verify together.
pub(all) struct AuditManifest {
  version : Int
  entries : Array[AuditManifestEntry]
}

///|
pub fn AuditManifest::new(
  version : Int,
  entries : Array[AuditManifestEntry],
) -> AuditManifest {
  { version, entries, }
}

///|
fn audit_manifest_version(
  object : Map[String, Json],
) -> Result[Int, AuditManifestError] {
  let value = match object.get("version") {
    None => return Err(AuditManifestMissingField("version"))
    Some(value) => value
  }
  guard value is Number(number, ..) else {
    return Err(AuditManifestInvalidField("version"))
  }
  if number.is_nan() || number.is_pos_inf() || number.is_neg_inf() {
    return Err(AuditManifestInvalidField("version"))
  }
  let version = number.to_int()
  if version.to_double() != number {
    return Err(AuditManifestInvalidField("version"))
  }
  if version != 1 {
    Err(AuditManifestUnsupportedVersion(version))
  } else {
    Ok(version)
  }
}

///|
fn audit_manifest_entry_string(
  object : Map[String, Json],
  index : Int,
  field : String,
) -> Result[String, AuditManifestError] {
  match object.get(field) {
    None => Err(AuditManifestMissingEntryField(index, field))
    Some(String(value)) =>
      if value.is_empty() {
        Err(AuditManifestEmptyEntryField(index, field))
      } else {
        Ok(value)
      }
    Some(_) => Err(AuditManifestInvalidEntryField(index, field))
  }
}

///|
fn parse_audit_manifest_entry(
  value : Json,
  index : Int,
) -> Result[AuditManifestEntry, AuditManifestError] {
  guard value is Object(object) else {
    return Err(AuditManifestInvalidEntry(index))
  }
  let name = match audit_manifest_entry_string(object, index, "name") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let artifact_path = match
    audit_manifest_entry_string(object, index, "artifact") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let envelope_path = match
    audit_manifest_entry_string(object, index, "envelope") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let policy_path = match audit_manifest_entry_string(object, index, "policy") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok(AuditManifestEntry::new(name, artifact_path, envelope_path, policy_path))
}

///|
/// Parse an audit manifest. Version 1 contains a non-empty `entries` array;
/// every entry requires a unique non-empty name plus artifact, envelope, and
/// policy paths. Unknown fields are ignored for forward compatibility.
pub fn parse_audit_manifest(
  text : StringView,
) -> Result[AuditManifest, AuditManifestError] {
  let document = @json.parse(text) catch {
    _ => return Err(AuditManifestInvalidJson)
  }
  guard document is Object(object) else { return Err(AuditManifestNotObject) }
  let version = match audit_manifest_version(object) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let entry_values = match object.get("entries") {
    None => return Err(AuditManifestMissingField("entries"))
    Some(Array(values)) => values
    Some(_) => return Err(AuditManifestInvalidField("entries"))
  }
  guard !entry_values.is_empty() else { return Err(AuditManifestEmptyEntries) }
  let entries : Array[AuditManifestEntry] = []
  let names : Array[String] = []
  for index, value in entry_values {
    let entry = match parse_audit_manifest_entry(value, index) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    if names.contains(entry.name) {
      return Err(AuditManifestDuplicateName(entry.name))
    }
    names.push(entry.name)
    entries.push(entry)
  }
  Ok(AuditManifest::new(version, entries))
}
