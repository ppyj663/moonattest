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
/// The minimum provenance context used by the verifier.
pub(all) struct Provenance {
  builder_id : String
  source_uri : String
}

///|
pub fn Provenance::new(builder_id : String, source_uri : String) -> Provenance {
  { builder_id, source_uri, }
}

///|
/// An in-toto Statement carrying a SLSA provenance predicate.
pub(all) struct Statement {
  statement_type : String
  subjects : Array[Subject]
  predicate_type : String
  predicate : Json
}

///|
pub fn Statement::new(
  statement_type : String,
  subjects : Array[Subject],
  predicate_type : String,
  predicate : Json,
) -> Statement {
  { statement_type, subjects, predicate_type, predicate, }
}

///|
/// Explicit trust constraints. Empty strings mean that a constraint is disabled.
pub(all) struct Policy {
  digest_algorithm : String
  expected_digest : String
  source_uri : String
  builder_id : String
  trusted_key_ids : Array[String]
  subject_name : String
  min_valid_signatures : Int
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
    subject_name: "",
    min_valid_signatures: 1,
  }
}

///|
/// Return a copy of this policy that targets one named in-toto subject.
/// An empty name preserves the default behavior of checking the first subject.
pub fn Policy::with_subject(self : Policy, subject_name : String) -> Policy {
  {
    digest_algorithm: self.digest_algorithm,
    expected_digest: self.expected_digest,
    source_uri: self.source_uri,
    builder_id: self.builder_id,
    trusted_key_ids: self.trusted_key_ids,
    subject_name,
    min_valid_signatures: self.min_valid_signatures,
  }
}

///|
/// Return a copy of this policy requiring signatures from at least
/// `minimum` distinct trusted key IDs. The default is one.
pub fn Policy::with_min_valid_signatures(
  self : Policy,
  minimum : Int,
) -> Policy {
  {
    digest_algorithm: self.digest_algorithm,
    expected_digest: self.expected_digest,
    source_uri: self.source_uri,
    builder_id: self.builder_id,
    trusted_key_ids: self.trusted_key_ids,
    subject_name: self.subject_name,
    min_valid_signatures: minimum,
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
