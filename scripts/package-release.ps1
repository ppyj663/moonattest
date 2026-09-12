param(
  [Parameter(Mandatory = $true)]
  [string]$Tag
)

$ErrorActionPreference = "Stop"
$moonCommand = Get-Command moon -ErrorAction SilentlyContinue
$moon = if ($moonCommand) {
  $moonCommand.Source
} else {
  $suffix = if ($IsWindows) { ".exe" } else { "" }
  $candidate = Join-Path $HOME ".moon\bin\moon$suffix"
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "moon is not installed or available on PATH"
  }
  $candidate
}

$root = Split-Path -Parent $PSScriptRoot
$module = Get-Content -Raw -LiteralPath (Join-Path $root "moon.mod")
$versionMatch = [regex]::Match($module, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $versionMatch.Success) { throw "moon.mod does not declare a version" }
$version = $versionMatch.Groups[1].Value
$expectedTag = "v$version"
if ($Tag -ne $expectedTag) {
  throw "release tag $Tag does not match moon.mod version $version"
}

Set-Location $root
& $moon package --frozen
if ($LASTEXITCODE -ne 0) { throw "moon package failed" }

$packageName = "ppyj663-moonattest-$version.zip"
$packagePath = Join-Path $root "_build\publish\$packageName"
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
  throw "expected package was not generated: $packagePath"
}

$releaseDirectory = Join-Path $root "_build\release"
New-Item -ItemType Directory -Path $releaseDirectory -Force | Out-Null
Get-ChildItem -LiteralPath $releaseDirectory -File | Remove-Item -Force
$releasePackage = Join-Path $releaseDirectory $packageName
Copy-Item -LiteralPath $packagePath -Destination $releasePackage

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $releasePackage).Hash.ToLowerInvariant()
"$hash  $packageName" | Set-Content -LiteralPath (Join-Path $releaseDirectory "SHA256SUMS") -Encoding ascii

Write-Output "Release package ready: $releasePackage"
Write-Output "SHA-256: $hash"
