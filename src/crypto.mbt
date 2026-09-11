///|
/// Return the lowercase SHA-256 digest of a byte string.
pub fn sha256_hex(data : Bytes) -> String {
  let digest = @sha256.Digest::new()
  for byte in data {
    digest.write(byte)
  }
  digest.check_sum()
}

///|
fn verify_signature(
  envelope : Envelope,
  payload : String,
  signature : Signature,
  public_key_hex : String,
) -> Bool {
  let public_key = @hex.decode(public_key_hex.to_string_view()) catch {
    _ => return false
  }
  let signature_bytes = @base64.decode(signature.sig.to_string_view()) catch {
    _ => return false
  }
  let signing_input = @utf8.encode(
    pae(envelope.payload_type, payload).to_string_view(),
  )
  @ed25519.verify(public_key, signing_input, signature_bytes)
}
