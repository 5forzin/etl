param(
  [string]$RuntimeBin = 'C:\msys64\ucrt64\bin',
  [switch]$Portable
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$buildName = if ($Portable) { 'windows-portable' } else { 'windows' }
$built = Join-Path $root "build/$buildName/etl-client.exe"
if (-not (Test-Path -LiteralPath $built)) { throw 'Build the client with CMake first' }
$output = Join-Path $root "dist/$buildName"
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'etl-client.exe'
Copy-Item -LiteralPath $built -Destination $exe -Force
if ($Portable) {
  $objdump = Join-Path $RuntimeBin 'objdump.exe'
  if (-not (Test-Path -LiteralPath $objdump)) { throw "Missing dependency inspector: $objdump" }
  $imports = & $objdump -p $exe | Where-Object { $_ -match 'DLL Name:' }
  if ($LASTEXITCODE -ne 0 -or -not $imports) { throw 'Cannot inspect EXE dependencies' }
  if ($imports | Where-Object { $_ -match 'DLL Name:\s*(libssl|libcrypto|libwinpthread|libgcc|libstdc\+\+)' }) {
    throw "Portable EXE still imports an MSYS2 runtime library: $($imports -join ', ')"
  }
  $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
  [System.IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS'), "$hash  etl-client.exe`n")
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE-OpenSSL.txt') -Destination $output -Force
} else {
  foreach ($dll in @('libssl-3-x64.dll', 'libcrypto-3-x64.dll', 'libwinpthread-1.dll')) {
    $source = Join-Path $RuntimeBin $dll
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing runtime library: $dll" }
    Copy-Item -LiteralPath $source -Destination $output
  }
}
Get-ChildItem -LiteralPath $output | Select-Object Name, Length
