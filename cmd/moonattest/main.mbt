///|
extern "js" fn read_text_file(path : String) -> String? =
  #| function(path) {
  #|   try {
  #|     const fs = process.getBuiltinModule('node:fs');
  #|     return fs.readFileSync(path, 'utf8');
  #|   } catch (_) {
  #|     return undefined;
  #|   }
  #| }

///|
extern "js" fn read_binary_file_base64(path : String) -> String? =
  #| function(path) {
  #|   try {
  #|     const fs = process.getBuiltinModule('node:fs');
  #|     return fs.readFileSync(path).toString('base64');
  #|   } catch (_) {
  #|     return undefined;
  #|   }
  #| }

///|
extern "js" fn resolve_manifest_path(
  manifest_path : String,
  referenced_path : String,
) -> String =
  #| function(manifestPath, referencedPath) {
  #|   const path = process.getBuiltinModule('node:path');
  #|   return path.resolve(path.dirname(manifestPath), referencedPath);
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
  println("  moonattest audit <manifest.json> [--format text|json|markdown]")
  println(
    "  moonattest verify <envelope.json> (--digest <hex> | --artifact <path>) --source <uri> --builder <id> --public-key <keyid=hex>... [--build-type <uri>] [--subject <name>] [--min-signatures <n>] [--json]",
  )
}

///|
fn command_index(args : Array[String]) -> (String, Int)? {
  for i = 0; i < args.length(); i = i + 1 {
    match args[i] {
      "inspect" | "verify" | "audit" => return Some((args[i], i))
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
fn read_policy_document(path : String) -> @attest.PolicyDocument? {
  let text = match read_text_file(path) {
    Some(value) => value
    None => {
      println("error: cannot read " + path)
      return None
    }
  }
  match @attest.parse_policy_document(text.to_string_view()) {
    Ok(value) => Some(value)
    Err(_) => {
      println("error: invalid policy document " + path)
      None
    }
  }
}

///|
fn read_artifact_digest(path : String) -> String? {
  match read_binary_file_base64(path) {
    Some(encoded) => {
      let bytes = @base64.decode(encoded.to_string_view()) catch {
        _ => {
          println("error: cannot decode " + path)
          return None
        }
      }
      Some(@attest.sha256_hex(bytes))
    }
    None => {
      println("error: cannot read " + path)
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
fn print_batch_report(report : @attest.BatchReport) -> Unit {
  for result in report.results {
    let status = if result.report.ok { "PASS" } else { "FAIL" }
    println(result.name + ": " + status)
    for finding in result.report.findings {
      println("  " + finding.code + ": " + finding.message)
    }
  }
  println(
    "summary: " +
    report.passed.to_string() +
    " passed, " +
    report.failed.to_string() +
    " failed",
  )
  println(if report.ok { "AUDIT PASSED" } else { "AUDIT FAILED" })
}

///|
fn run_audit(args : Array[String], index : Int) -> Int {
  guard index + 1 < args.length() else {
    usage()
    return 2
  }
  let manifest_path = args[index + 1]
  let requested_format = option_value(args, index + 2, "--format")
  if has_flag(args, index + 2, "--format") && requested_format is None {
    println("error: --format requires text, json, or markdown")
    return 2
  }
  let format = match requested_format {
    Some(value) => value
    None => "text"
  }
  if format != "text" && format != "json" && format != "markdown" {
    println("error: --format must be text, json, or markdown")
    return 2
  }
  let manifest_text = match read_text_file(manifest_path) {
    Some(value) => value
    None => {
      println("error: cannot read " + manifest_path)
      return 2
    }
  }
  let manifest = match
    @attest.parse_audit_manifest(manifest_text.to_string_view()) {
    Ok(value) => value
    Err(_) => {
      println("error: invalid audit manifest " + manifest_path)
      return 2
    }
  }
  let entries : Array[@attest.BatchEntry] = []
  for entry in manifest.entries {
    let artifact_path = resolve_manifest_path(
      manifest_path,
      entry.artifact_path,
    )
    let envelope_path = resolve_manifest_path(
      manifest_path,
      entry.envelope_path,
    )
    let policy_path = resolve_manifest_path(manifest_path, entry.policy_path)
    let envelope = match read_envelope(envelope_path) {
      Some(value) => value
      None => return 2
    }
    let policy_document = match read_policy_document(policy_path) {
      Some(value) => value
      None => return 2
    }
    let artifact_digest = match read_artifact_digest(artifact_path) {
      Some(value) => value
      None => return 2
    }
    let bound_policy = @attest.PolicyDocument::new(
      policy_document.policy.with_artifact_digest(artifact_digest),
      policy_document.trusted_keys,
    )
    entries.push(@attest.BatchEntry::new(entry.name, envelope, bound_policy))
  }
  let report = match @attest.verify_batch(entries) {
    Ok(value) => value
    Err(_) => {
      println("error: audit manifest cannot be verified")
      return 2
    }
  }
  match format {
    "json" => println(@attest.batch_report_json(report))
    "markdown" => println(@attest.batch_report_markdown(report))
    _ => print_batch_report(report)
  }
  if report.ok {
    0
  } else {
    1
  }
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
  let digest_option = option_value(args, index + 2, "--digest")
  let artifact_option = option_value(args, index + 2, "--artifact")
  if digest_option is Some(_) && artifact_option is Some(_) {
    println("error: --digest and --artifact are mutually exclusive")
    return 2
  }
  let digest = match (digest_option, artifact_option) {
    (Some(value), None) => {
      if !@attest.is_valid_sha256_digest(value) {
        println("error: --digest must be a 32-byte hexadecimal SHA-256 value")
        return 2
      }
      value
    }
    (None, Some(artifact_path)) =>
      match read_artifact_digest(artifact_path) {
        Some(value) => value
        None => return 2
      }
    _ => {
      println("error: either --digest or --artifact is required")
      return 2
    }
  }
  let source = match option_value(args, index + 2, "--source") {
    Some(value) => {
      if value.is_empty() {
        println("error: --source must not be empty")
        return 2
      }
      value
    }
    None => {
      println("error: --source is required")
      return 2
    }
  }
  let builder = match option_value(args, index + 2, "--builder") {
    Some(value) => {
      if value.is_empty() {
        println("error: --builder must not be empty")
        return 2
      }
      value
    }
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
  let policy = match option_value(args, index + 2, "--build-type") {
    Some(build_type) => {
      if build_type.is_empty() {
        println("error: --build-type must not be empty")
        return 2
      }
      policy.with_build_type(build_type)
    }
    None => policy
  }
  let policy = match option_value(args, index + 2, "--subject") {
    Some(subject) => {
      if subject.is_empty() {
        println("error: --subject must not be empty")
        return 2
      }
      policy.with_subject(subject)
    }
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
    Some(("audit", index)) => set_process_exit_code(run_audit(args, index))
    _ => {
      usage()
      set_process_exit_code(2)
    }
  }
}
