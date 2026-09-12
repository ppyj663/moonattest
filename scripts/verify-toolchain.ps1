param(
  [Parameter(Mandatory = $true)]
  [string]$MoonVersion,
  [Parameter(Mandatory = $true)]
  [string]$MooncVersion,
  [Parameter(Mandatory = $true)]
  [string]$MoonSha256,
  [Parameter(Mandatory = $true)]
  [string]$MooncSha256,
  [Parameter(Mandatory = $true)]
  [string]$MoonrunSha256,
  [string]$BinDirectory = (Join-Path $HOME ".moon\bin")
)

$ErrorActionPreference = "Stop"

function Assert-FileHash([string]$Path, [string]$Expected) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "toolchain file is missing: $Path"
  }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  if ($actual -ne $Expected.ToLowerInvariant()) {
    throw "SHA-256 mismatch for $Path`: expected $Expected, got $actual"
  }
}

$suffix = if ($IsWindows) { ".exe" } else { "" }
$moon = Join-Path $BinDirectory "moon$suffix"
$moonc = Join-Path $BinDirectory "moonc$suffix"
$moonrun = Join-Path $BinDirectory "moonrun$suffix"

Assert-FileHash $moon $MoonSha256
Assert-FileHash $moonc $MooncSha256
Assert-FileHash $moonrun $MoonrunSha256

$versions = & $moon version --all | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "moon version --all failed"
}
if (-not $versions.Contains("moon $MoonVersion ")) {
  throw "expected moon $MoonVersion"
}
if (-not $versions.Contains("moonc $MooncVersion ")) {
  throw "expected moonc $MooncVersion"
}
if (-not $versions.Contains("moonrun $MoonVersion ")) {
  throw "expected moonrun $MoonVersion"
}

Write-Output "Verified MoonBit $MoonVersion toolchain versions and SHA-256 checksums"
