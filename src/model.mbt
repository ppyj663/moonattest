///|
/// A DSSE signature identified by the key that produced it.
pub(all) struct Signature {
  key_id : String
  sig : String
}

///|
pub fn Signature::new(key_id : String, sig : String) -> Signature {
  { key_id, sig, }
}

///|
/// A DSSE envelope before payload decoding.
pub(all) struct Envelope {
  payload_type : String
  payload : String
  signatures : Array[Signature]
}

///|
pub fn Envelope::new(
  payload_type : String,
  payload : String,
  signatures : Array[Signature],
) -> Envelope {
  { payload_type, payload, signatures, }
}

///|
/// A named artifact subject and its content digest.
pub(all) struct Subject {
  name : String
  digest_algorithm : String
  digest : String
}

///|
pub fn Subject::new(
  name : String,
  digest_algorithm : String,
  digest : String,
) -> Subject {
  { name, digest_algorithm, digest, }
}

///|
/// The minimum provenance context used by the first verifier.
pub(all) struct Provenance {
  builder_id : String
  source_uri : String
}

///|
pub fn Provenance::new(builder_id : String, source_uri : String) -> Provenance {
  { builder_id, source_uri, }
}

///|
/// Explicit trust constraints. Empty strings mean that a constraint is disabled.
pub(all) struct Policy {
  digest_algorithm : String
  expected_digest : String
  source_uri : String
  builder_id : String
  trusted_key_ids : Array[String]
}

///|
pub fn Policy::new(
  digest_algorithm : String,
  expected_digest : String,
  source_uri : String,
  builder_id : String,
  trusted_key_ids : Array[String],
) -> Policy {
  {
    digest_algorithm,
    expected_digest,
    source_uri,
    builder_id,
    trusted_key_ids,
  }
}

///|
/// A stable diagnostic emitted by verification.
pub(all) struct Finding {
  code : String
  message : String
}

///|
pub fn Finding::new(code : String, message : String) -> Finding {
  { code, message, }
}

///|
/// Verification result with all diagnostics collected in order.
pub(all) struct Report {
  ok : Bool
  findings : Array[Finding]
}

///|
pub fn Report::new(ok : Bool, findings : Array[Finding]) -> Report {
  { ok, findings, }
}
