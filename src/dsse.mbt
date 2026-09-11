///|
/// Errors returned while decoding a DSSE envelope.
pub suberror DsseError {
  InvalidJson
  NotObject
  MissingField(String)
  InvalidField(String)
  EmptySignatures
  InvalidBase64(String)
}

///|
fn required_string(
  object : Map[String, Json],
  field : String,
) -> Result[String, DsseError] {
  match object.get(field) {
    None => Err(MissingField(field))
    Some(String(value)) => Ok(value)
    Some(_) => Err(InvalidField(field))
  }
}

///|
fn validate_base64(value : String, field : String) -> Result[Unit, DsseError] {
  let _ = @base64.decode(value.to_string_view()) catch {
    _ => return Err(InvalidBase64(field))
  }
  Ok(())
}

///|
/// Decode and validate the required fields of a DSSE envelope.
/// Unknown JSON fields are intentionally ignored for forward compatibility.
pub fn parse_envelope(text : StringView) -> Result[Envelope, DsseError] {
  let document = @json.parse(text) catch { _ => return Err(InvalidJson) }
  guard document is Object(object) else { return Err(NotObject) }
  let payload_type = match required_string(object, "payloadType") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let payload = match required_string(object, "payload") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match validate_base64(payload, "payload") {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let signature_values = match object.get("signatures") {
    None => return Err(MissingField("signatures"))
    Some(Array(values)) => values
    Some(_) => return Err(InvalidField("signatures"))
  }
  guard !signature_values.is_empty() else { return Err(EmptySignatures) }
  let signatures : Array[Signature] = []
  for value in signature_values {
    guard value is Object(signature_object) else {
      return Err(InvalidField("signatures"))
    }
    let key_id = match required_string(signature_object, "keyid") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let sig = match required_string(signature_object, "sig") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    match validate_base64(sig, "signatures.sig") {
      Ok(_) => ()
      Err(error) => return Err(error)
    }
    signatures.push(Signature::new(key_id, sig))
  }
  Ok(Envelope::new(payload_type, payload, signatures))
}

///|
fn decimal_byte_length(value : String) -> String {
  @utf8.encode(value.to_string_view()).length().to_string()
}

///|
/// Build the DSSE v1 pre-authentication encoding (PAE).
pub fn pae(payload_type : String, payload : String) -> String {
  "DSSEv1 " +
  decimal_byte_length(payload_type) +
  " " +
  payload_type +
  " " +
  decimal_byte_length(payload) +
  " " +
  payload
}
