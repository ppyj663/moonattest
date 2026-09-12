///|
extern "js" fn read_text_file(path : String) -> String? =
  #| function(path) {
  #|   try {
  #|     const fs = process.getBuiltinModule('node:fs');
  #|     return fs.readFileSync(path, 'utf8');
  #|   } catch (_) {
  #|     return null;
  #|   }
  #| }

///|
extern "js" fn set_process_exit_code(code : Int) -> Unit =
  #| function(code) {
  #|   if (typeof process !== 'undefined') process.exitCode = code;
  #| }

///|
fn usage() -> Unit {
  println("MoonAttest - offline DSSE/SLSA verifier")
  println("Usage:")
  println("  moonattest inspect <envelope.json>")
  println(
    "  moonattest verify <envelope.json> --digest <hex> --source <uri> --builder <id> --public-key <keyid=hex>... [--subject <name>] [--min-signatures <n>] [--json]",
  )
}

///|
fn command_index(args : Array[String]) -> (String, Int)? {
  for i = 0; i < args.length(); i = i + 1 {
    match args[i] {
      "inspect" | "verify" => return Some((args[i], i))
      _ => ()
    }
  }
  None
}

///|
fn option_value(args : Array[String], start : Int, name : String) -> String? {
  for i = start; i + 1 < args.length(); i = i + 1 {
    if args[i] == name {
      return Some(args[i + 1])
    }
  }
  None
}

///|
fn has_flag(args : Array[String], start : Int, name : String) -> Bool {
  for i = start; i < args.length(); i = i + 1 {
    if args[i] == name {
      return true
    }
  }
  false
}

///|
fn report_json(report : @attest.Report) -> String {
  let output = StringBuilder()
  output.write_string(
    if report.ok {
      "{\"ok\":true,\"findings\":["
    } else {
      "{\"ok\":false,\"findings\":["
    },
  )
  for i, finding in report.findings {
    if i > 0 {
      output.write_string(",")
    }
    output.write_string("{\"code\":")
    output.write_string(finding.code.escape())
    output.write_string(",\"message\":")
    output.write_string(finding.message.escape())
    output.write_string("}")
  }
  output.write_string("]}")
  output.to_string()
}

///|
fn read_envelope(path : String) -> @attest.Envelope? {
  let text = match read_text_file(path) {
    Some(value) => value
    None => {
      println("error: cannot read " + path)
      return None
    }
  }
  match @attest.parse_envelope(text.to_string_view()) {
    Ok(value) => Some(value)
    Err(_) => {
      println("error: invalid DSSE envelope")
      None
    }
  }
}

///|
fn run_inspect(args : Array[String], index : Int) -> Int {
  guard index + 1 < args.length() else {
    usage()
    return 2
  }
  let path = args[index + 1]
  let envelope = match read_envelope(path) {
    Some(value) => value
    None => return 2
  }
  println("payloadType: " + envelope.payload_type)
  println("signatures: " + envelope.signatures.length().to_string())
  println("status: parsed")
  0
}

///|
fn parse_public_key(value : String) -> (String, String)? {
  match value.split_once("=") {
    Some((key_id, public_key)) =>
      Some((key_id.to_owned(), public_key.to_owned()))
    None => None
  }
}

///|
fn valid_public_key_hex(value : String) -> Bool {
  let decoded = @hex.decode(value.to_string_view()) catch { _ => return false }
  decoded.length() == 32
}

///|
fn parse_public_keys(
  args : Array[String],
  start : Int,
) -> (Array[(String, String)], String?) {
  let pairs : Array[(String, String)] = []
  for i = start; i < args.length(); i = i + 1 {
    if args[i] == "--public-key" {
      if i + 1 >= args.length() {
        return (pairs, Some("--public-key requires keyid=hex"))
      }
      let pair = match parse_public_key(args[i + 1]) {
        Some(value) => value
        None => return (pairs, Some("--public-key must be keyid=hex"))
      }
      if pair.0.is_empty() {
        return (pairs, Some("--public-key key ID must not be empty"))
      }
      if !valid_public_key_hex(pair.1) {
        return (pairs, Some("--public-key must be a 32-byte hex public key"))
      }
      for existing in pairs {
        if existing.0 == pair.0 {
          return (pairs, Some("--public-key key IDs must be unique"))
        }
      }
      pairs.push(pair)
    }
  }
  (pairs, None)
}

///|
fn parse_int(value : String) -> Int? {
  let parsed = @string.parse_int(value.to_string_view()) catch {
    _ => return None
  }
  Some(parsed)
}

///|
fn run_verify(args : Array[String], index : Int) -> Int {
  guard index + 1 < args.length() else {
    usage()
    return 2
  }
  let path = args[index + 1]
  let digest = match option_value(args, index + 2, "--digest") {
    Some(value) => value
    None => {
      println("error: --digest is required")
      return 2
    }
  }
  if !@attest.is_valid_sha256_digest(digest) {
    println("error: --digest must be a 32-byte hexadecimal SHA-256 value")
    return 2
  }
  let source = match option_value(args, index + 2, "--source") {
    Some(value) => value
    None => {
      println("error: --source is required")
      return 2
    }
  }
  let builder = match option_value(args, index + 2, "--builder") {
    Some(value) => value
    None => {
      println("error: --builder is required")
      return 2
    }
  }
  let (public_keys, public_key_error) = parse_public_keys(args, index + 2)
  match public_key_error {
    Some(message) => {
      println("error: " + message)
      return 2
    }
    None => ()
  }
  if public_keys.is_empty() {
    println("error: --public-key is required")
    return 2
  }
  let envelope = match read_envelope(path) {
    Some(value) => value
    None => return 2
  }
  let trusted_key_ids : Array[String] = []
  for pair in public_keys {
    trusted_key_ids.push(pair.0)
  }
  let keys = Map(public_keys)
  let policy = @attest.Policy::new(
    "sha256", digest, source, builder, trusted_key_ids,
  )
  let policy = match option_value(args, index + 2, "--subject") {
    Some(subject) => policy.with_subject(subject)
    None => policy
  }
  let policy = match option_value(args, index + 2, "--min-signatures") {
    Some(value) =>
      match parse_int(value) {
        Some(minimum) => policy.with_min_valid_signatures(minimum)
        None => {
          println("error: --min-signatures must be an integer")
          return 2
        }
      }
    None => policy
  }
  let report = @attest.verify_envelope(envelope, policy, keys)
  let json = has_flag(args, index + 2, "--json")
  if json {
    println(report_json(report))
    return if report.ok { 0 } else { 1 }
  }
  for finding in report.findings {
    println(finding.code + ": " + finding.message)
  }
  if report.ok {
    println("VERIFIED")
    0
  } else {
    println("REJECTED")
    1
  }
}

///|
fn main {
  let args = @env.args()
  match command_index(args) {
    Some(("inspect", index)) => set_process_exit_code(run_inspect(args, index))
    Some(("verify", index)) => set_process_exit_code(run_verify(args, index))
    _ => {
      usage()
      set_process_exit_code(2)
    }
  }
}
