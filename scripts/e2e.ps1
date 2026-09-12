$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$moon = if (Get-Command moon -ErrorAction SilentlyContinue) { "moon" } else { "C:\Users\3i\.moon\bin\moon.exe" }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Assert-Contains([string]$Text, [string]$Needle, [string]$Message) {
  if (-not $Text.Contains($Needle)) { throw $Message }
}

$inspect = & $moon run cmd/moonattest inspect fixtures/dsse/valid-envelope.json | Out-String
if ($LASTEXITCODE -ne 0) { throw "inspect should exit 0" }
Assert-Contains $inspect "status: parsed" "inspect output missing parsed status"

$tempRoot = [IO.Path]::GetTempPath()
$valid = Join-Path $tempRoot ("moonattest-valid-" + [Guid]::NewGuid().ToString("N") + ".json")
$tampered = Join-Path $tempRoot ("moonattest-tampered-" + [Guid]::NewGuid().ToString("N") + ".json")
$multi = Join-Path $tempRoot ("moonattest-multi-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
  & node (Join-Path $PSScriptRoot "create-demo-envelope.mjs") $valid
  if ($LASTEXITCODE -ne 0) { throw "demo envelope generation failed" }
  & node (Join-Path $PSScriptRoot "create-demo-envelope.mjs") $multi --two-signatures
  if ($LASTEXITCODE -ne 0) { throw "multi-signature demo envelope generation failed" }
  $publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  $backupPublicKey = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
  $artifactDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  $otherDigest = "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34"
  $verifyArgs = @(
    "run", "cmd/moonattest", "verify", $valid,
    "--digest", $artifactDigest,
    "--source", "https://github.com/example/project",
    "--builder", "https://builder.example/id",
    "--public-key", "release-key=$publicKey"
  )
  $verified = & $moon @verifyArgs | Out-String
  if ($LASTEXITCODE -ne 0) { throw "valid verify should exit 0`n$verified" }
  Assert-Contains $verified "VERIFIED" "valid verify output missing VERIFIED"

  $multiVerifyArgs = @(
    "run", "cmd/moonattest", "verify", $multi,
    "--digest", $artifactDigest,
    "--source", "https://github.com/example/project",
    "--builder", "https://builder.example/id",
    "--public-key", "release-key=$publicKey",
    "--public-key", "backup-key=$backupPublicKey",
    "--min-signatures", "2"
  )
  $multiVerified = & $moon @multiVerifyArgs | Out-String
  if ($LASTEXITCODE -ne 0) { throw "multi-signature verify should exit 0`n$multiVerified" }
  Assert-Contains $multiVerified "VERIFIED" "multi-signature verify output missing VERIFIED"

  $duplicateKey = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 2) { throw "duplicate CLI key IDs should exit 2" }
  Assert-Contains $duplicateKey "key IDs must be unique" "duplicate CLI key IDs were not rejected"

  $invalidKey = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=abcd" | Out-String
  if ($LASTEXITCODE -ne 2) { throw "invalid CLI public key should exit 2" }
  Assert-Contains $invalidKey "must be a 32-byte hex public key" "invalid CLI public key was not rejected"

  $invalidDigest = & $moon run cmd/moonattest verify $valid --digest abc123 --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 2) { throw "invalid CLI digest should exit 2" }
  Assert-Contains $invalidDigest "must be a 32-byte hexadecimal SHA-256 value" "invalid CLI digest was not rejected"

  $jsonVerify = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" --json | Out-String
  if ($LASTEXITCODE -ne 0) { throw "JSON verify should exit 0`n$jsonVerify" }
  Assert-Contains $jsonVerify '"ok":true' "JSON verify output missing ok=true"
  Assert-Contains $jsonVerify '"findings":[]' "JSON verify output missing empty findings"

  $namedSubject = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" --subject artifact.bin | Out-String
  if ($LASTEXITCODE -ne 0) { throw "named subject verify should exit 0`n$namedSubject" }
  Assert-Contains $namedSubject "VERIFIED" "named subject verify output missing VERIFIED"

  $missingSubject = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" --subject missing.bin | Out-String
  if ($LASTEXITCODE -ne 1) { throw "missing subject should exit 1" }
  Assert-Contains $missingSubject "SUBJECT_NOT_FOUND" "missing subject was not reported"

  $thresholdMismatch = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" --min-signatures 2 | Out-String
  if ($LASTEXITCODE -ne 1) { throw "signature threshold mismatch should exit 1" }
  Assert-Contains $thresholdMismatch "SIGNATURE_THRESHOLD_UNMET" "signature threshold mismatch was not reported"

  $invalidThreshold = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" --min-signatures nope | Out-String
  if ($LASTEXITCODE -ne 2) { throw "invalid signature threshold should exit 2" }
  Assert-Contains $invalidThreshold "--min-signatures must be an integer" "invalid signature threshold was not reported"

  $wrongType = Join-Path $tempRoot ("moonattest-wrong-type-" + [Guid]::NewGuid().ToString("N") + ".json")
  $envelope = Get-Content -Raw -LiteralPath $valid | ConvertFrom-Json
  $envelope.payloadType = "application/octet-stream"
  $envelope | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $wrongType -Encoding utf8
  try {
    $typeMismatch = & $moon run cmd/moonattest verify $wrongType --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
    if ($LASTEXITCODE -ne 1) { throw "payload type mismatch should exit 1" }
    Assert-Contains $typeMismatch "PAYLOAD_TYPE_MISMATCH" "payload type mismatch was not reported"
  } finally {
    Remove-Item -LiteralPath $wrongType -Force -ErrorAction SilentlyContinue
  }

  $sourceMismatch = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/other/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "source mismatch should exit 1" }
  Assert-Contains $sourceMismatch "SOURCE_MISMATCH" "source mismatch was not reported"

  $builderMismatch = & $moon run cmd/moonattest verify $valid --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/other --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "builder mismatch should exit 1" }
  Assert-Contains $builderMismatch "BUILDER_MISMATCH" "builder mismatch was not reported"

  $digestMismatch = & $moon run cmd/moonattest verify $valid --digest $otherDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "digest mismatch should exit 1" }
  Assert-Contains $digestMismatch "DIGEST_MISMATCH" "digest mismatch was not reported"

  $envelope = Get-Content -Raw -LiteralPath $valid | ConvertFrom-Json
  $envelope.signatures[0].sig = "AAAA"
  $envelope | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tampered -Encoding utf8
  $signatureMismatch = & $moon run cmd/moonattest verify $tampered --digest $artifactDigest --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "signature mismatch should exit 1" }
  Assert-Contains $signatureMismatch "SIGNATURE_INVALID" "signature mismatch was not reported"

  $invalid = & $moon run cmd/moonattest inspect fixtures/dsse/invalid-base64.json | Out-String
  if ($LASTEXITCODE -ne 2) { throw "invalid base64 inspect should exit 2" }
  Assert-Contains $invalid "invalid DSSE envelope" "invalid base64 was not reported"
  Write-Output "E2E PASS: inspect, single/multi-signature verify, policy/tamper failures"
} finally {
  Remove-Item -LiteralPath $valid, $tampered, $multi -Force -ErrorAction SilentlyContinue
}
