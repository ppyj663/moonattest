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
    "  moonattest verify <envelope.json> --digest <hex> --source <uri> --builder <id> --public-key <keyid=hex>",
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
  let public_key = match option_value(args, index + 2, "--public-key") {
    Some(value) =>
      match parse_public_key(value) {
        Some(pair) => pair
        None => {
          println("error: --public-key must be keyid=hex")
          return 2
        }
      }
    None => {
      println("error: --public-key is required")
      return 2
    }
  }
  let envelope = match read_envelope(path) {
    Some(value) => value
    None => return 2
  }
  let keys = Map([public_key])
  let policy = @attest.Policy::new("sha256", digest, source, builder, [
    public_key.0,
  ])
  let report = @attest.verify_envelope(envelope, policy, keys)
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
