param(
  [ValidateRange(0, 100)]
  [int]$MinimumPercent = 70
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
$reportDirectory = Join-Path $root "_build\coverage"
$summaryPath = Join-Path $reportDirectory "summary.txt"
$coberturaPath = Join-Path $reportDirectory "cobertura.xml"

Set-Location $root
New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null

& $moon coverage clean
if ($LASTEXITCODE -ne 0) { throw "moon coverage clean failed" }

& $moon test --target js --enable-coverage
if ($LASTEXITCODE -ne 0) { throw "coverage test run failed" }

$summary = & $moon coverage report -f summary -p ppyj663/moonattest/src | Out-String
if ($LASTEXITCODE -ne 0) { throw "coverage summary generation failed" }
$summary.TrimEnd() | Set-Content -LiteralPath $summaryPath -Encoding utf8
Write-Output $summary.TrimEnd()

& $moon coverage report -f cobertura -p ppyj663/moonattest/src -o $coberturaPath
if ($LASTEXITCODE -ne 0) { throw "Cobertura report generation failed" }

$totalMatch = [regex]::Match($summary, "Total:\s+(\d+)/(\d+)")
if (-not $totalMatch.Success) { throw "coverage summary is missing its total" }
$covered = [int]$totalMatch.Groups[1].Value
$total = [int]$totalMatch.Groups[2].Value
if ($total -eq 0) { throw "coverage report contains no branch points" }
$percent = [Math]::Round(($covered * 100.0) / $total, 1)
if ($covered * 100 -lt $total * $MinimumPercent) {
  throw "branch coverage $percent% is below the required $MinimumPercent%"
}

Write-Output "Coverage PASS: $covered/$total branch points ($percent%, minimum $MinimumPercent%)"
