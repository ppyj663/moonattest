$ErrorActionPreference = "Stop"
$moon = "C:\Users\3i\.moon\bin\moon.exe"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Assert-Contains([string]$Text, [string]$Needle, [string]$Message) {
  if (-not $Text.Contains($Needle)) { throw $Message }
}

$inspect = & $moon run cmd/moonattest inspect fixtures/dsse/valid-envelope.json | Out-String
if ($LASTEXITCODE -ne 0) { throw "inspect should exit 0" }
Assert-Contains $inspect "status: parsed" "inspect output missing parsed status"

$valid = Join-Path $env:TEMP ("moonattest-valid-" + [Guid]::NewGuid().ToString("N") + ".json")
$tampered = Join-Path $env:TEMP ("moonattest-tampered-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
  & node (Join-Path $PSScriptRoot "create-demo-envelope.mjs") $valid
  if ($LASTEXITCODE -ne 0) { throw "demo envelope generation failed" }
  $publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  $verifyArgs = @(
    "run", "cmd/moonattest", "verify", $valid,
    "--digest", "abc123",
    "--source", "https://github.com/example/project",
    "--builder", "https://builder.example/id",
    "--public-key", "release-key=$publicKey"
  )
  $verified = & $moon @verifyArgs | Out-String
  if ($LASTEXITCODE -ne 0) { throw "valid verify should exit 0`n$verified" }
  Assert-Contains $verified "VERIFIED" "valid verify output missing VERIFIED"

  $sourceMismatch = & $moon run cmd/moonattest verify $valid --digest abc123 --source https://github.com/other/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "source mismatch should exit 1" }
  Assert-Contains $sourceMismatch "SOURCE_MISMATCH" "source mismatch was not reported"

  $builderMismatch = & $moon run cmd/moonattest verify $valid --digest abc123 --source https://github.com/example/project --builder https://builder.example/other --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "builder mismatch should exit 1" }
  Assert-Contains $builderMismatch "BUILDER_MISMATCH" "builder mismatch was not reported"

  $digestMismatch = & $moon run cmd/moonattest verify $valid --digest deadbeef --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "digest mismatch should exit 1" }
  Assert-Contains $digestMismatch "DIGEST_MISMATCH" "digest mismatch was not reported"

  $envelope = Get-Content -Raw -LiteralPath $valid | ConvertFrom-Json
  $envelope.signatures[0].sig = "AAAA"
  $envelope | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tampered -Encoding utf8
  $signatureMismatch = & $moon run cmd/moonattest verify $tampered --digest abc123 --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=$publicKey" | Out-String
  if ($LASTEXITCODE -ne 1) { throw "signature mismatch should exit 1" }
  Assert-Contains $signatureMismatch "SIGNATURE_INVALID" "signature mismatch was not reported"

  $invalid = & $moon run cmd/moonattest inspect fixtures/dsse/invalid-base64.json | Out-String
  if ($LASTEXITCODE -ne 2) { throw "invalid base64 inspect should exit 2" }
  Assert-Contains $invalid "invalid DSSE envelope" "invalid base64 was not reported"
  Write-Output "E2E PASS: inspect, valid verify, four policy/tamper failures"
} finally {
  Remove-Item -LiteralPath $valid, $tampered -Force -ErrorAction SilentlyContinue
}
