///|
/// Render a batch report as deterministic JSON for CI and release tooling.
pub fn batch_report_json(report : BatchReport) -> String {
  let output = StringBuilder()
  output.write_string("{\"ok\":")
  output.write_string(if report.ok { "true" } else { "false" })
  output.write_string(",\"passed\":")
  output.write_string(report.passed.to_string())
  output.write_string(",\"failed\":")
  output.write_string(report.failed.to_string())
  output.write_string(",\"results\":[")
  for i, result in report.results {
    if i > 0 {
      output.write_string(",")
    }
    output.write_string("{\"name\":")
    output.write_string(result.name.escape())
    output.write_string(",\"digestAlgorithm\":")
    output.write_string(result.digest_algorithm.escape())
    output.write_string(",\"expectedDigest\":")
    output.write_string(result.expected_digest.escape())
    output.write_string(",\"artifactDigest\":")
    output.write_string(result.artifact_digest.escape())
    output.write_string(",\"ok\":")
    output.write_string(if result.report.ok { "true" } else { "false" })
    output.write_string(",\"findings\":[")
    for j, finding in result.report.findings {
      if j > 0 {
        output.write_string(",")
      }
      output.write_string("{\"code\":")
      output.write_string(finding.code.escape())
      output.write_string(",\"message\":")
      output.write_string(finding.message.escape())
      output.write_string("}")
    }
    output.write_string("]}")
  }
  output.write_string("]}")
  output.to_string()
}

///|
/// Render a batch report as a compact Markdown audit suitable for a release
/// note or a CI job summary.
pub fn batch_report_markdown(report : BatchReport) -> String {
  let output = StringBuilder()
  output.write_string("# MoonAttest batch audit\n\n")
  output.write_string("- Status: ")
  output.write_string(if report.ok { "**PASSED**" } else { "**FAILED**" })
  output.write_string("\n- Passed: ")
  output.write_string(report.passed.to_string())
  output.write_string("\n- Failed: ")
  output.write_string(report.failed.to_string())
  output.write_string("\n\n")
  for i, result in report.results {
    output.write_string("## ")
    output.write_string(result.name)
    output.write_string(
      if result.report.ok {
        " — PASS\n\n"
      } else {
        " — FAIL\n\n"
      },
    )
    if result.expected_digest != "" {
      output.write_string("- Policy digest (`")
      output.write_string(result.digest_algorithm)
      output.write_string("`): `")
      output.write_string(result.expected_digest)
      output.write_string("`\n")
    }
    if result.artifact_digest != "" {
      output.write_string("- Artifact digest (`sha256`): `")
      output.write_string(result.artifact_digest)
      output.write_string("`\n")
    }
    if result.report.findings.is_empty() {
      output.write_string("No findings.\n")
    } else {
      for finding in result.report.findings {
        output.write_string("- `")
        output.write_string(finding.code)
        output.write_string("`: ")
        output.write_string(finding.message)
        output.write_string("\n")
      }
    }
    if i + 1 < report.results.length() {
      output.write_string("\n")
    }
  }
  output.to_string()
}
