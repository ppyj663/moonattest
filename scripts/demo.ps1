$ErrorActionPreference = "Stop"
$moon = if (Get-Command moon -ErrorAction SilentlyContinue) { "moon" } else { "C:\Users\3i\.moon\bin\moon.exe" }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$valid = Join-Path $env:TEMP ("moonattest-demo-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
  & node (Join-Path $PSScriptRoot "create-demo-envelope.mjs") $valid
  & $moon run cmd/moonattest inspect $valid
  & $moon run cmd/moonattest verify $valid --digest ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad --source https://github.com/example/project --builder https://builder.example/id --public-key "release-key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
} finally {
  Remove-Item -LiteralPath $valid -Force -ErrorAction SilentlyContinue
}
