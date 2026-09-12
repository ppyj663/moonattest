$ErrorActionPreference = "Stop"
$moon = if (Get-Command moon -ErrorAction SilentlyContinue) { "moon" } else { "C:\Users\3i\.moon\bin\moon.exe" }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$tempRoot = [IO.Path]::GetTempPath()
$valid = Join-Path $tempRoot ("moonattest-demo-" + [Guid]::NewGuid().ToString("N") + ".json")
$artifact = Join-Path $tempRoot ("moonattest-demo-artifact-" + [Guid]::NewGuid().ToString("N") + ".bin")
try {
  & node (Join-Path $PSScriptRoot "create-demo-envelope.mjs") $valid
  [IO.File]::WriteAllBytes($artifact, [Text.Encoding]::UTF8.GetBytes("abc"))
  & $moon run cmd/moonattest inspect $valid
  & $moon run cmd/moonattest verify $valid --artifact $artifact --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
} finally {
  Remove-Item -LiteralPath $valid, $artifact -Force -ErrorAction SilentlyContinue
}
