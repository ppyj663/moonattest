$ErrorActionPreference = "Stop"
$moon = "C:\Users\3i\.moon\bin\moon.exe"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$valid = Join-Path $env:TEMP ("moonattest-demo-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
  & node (Join-Path $PSScriptRoot "create-demo-envelope.mjs") $valid
  & $moon run cmd/moonattest inspect $valid
  & $moon run cmd/moonattest verify $valid --digest abc123 --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
} finally {
  Remove-Item -LiteralPath $valid -Force -ErrorAction SilentlyContinue
}
