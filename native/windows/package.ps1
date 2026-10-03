param(
  [string]$RuntimeBin = 'C:\msys64\ucrt64\bin',
  [string]$OutputDirectory = '',
  [switch]$Portable
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$buildName = if ($Portable) { 'windows-portable' } else { 'windows' }
$built = Join-Path $root "build/$buildName/etl-client.exe"
if (-not (Test-Path -LiteralPath $built)) { $built = Join-Path $root "build/$buildName/Release/etl-client.exe" }
if (-not (Test-Path -LiteralPath $built)) { throw 'Build the client with CMake first' }
$output = if (-not $OutputDirectory) { Join-Path $root "dist/$buildName" }
  elseif ([System.IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory }
  else { Join-Path $root $OutputDirectory }
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'etl-client.exe'
Copy-Item -LiteralPath $built -Destination $exe -Force
if ($Portable) {
  $objdump = Join-Path $RuntimeBin 'objdump.exe'
  if (Test-Path -LiteralPath $objdump) {
    $imports = & $objdump -p $exe | Where-Object { $_ -match 'DLL Name:' }
  } else {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'No objdump or Visual Studio dependency inspector' }
    $vs = & $vswhere -latest -property installationPath
    $compiler = Get-ChildItem -LiteralPath (Join-Path $vs 'VC/Tools/MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
    $dumpbin = Join-Path $compiler.FullName 'bin/Hostx64/x64/dumpbin.exe'
    $imports = & $dumpbin /DEPENDENTS $exe | Where-Object { $_ -match '^\s+\S+\.dll\s*$' }
  }
  if ($LASTEXITCODE -ne 0 -or -not $imports) { throw 'Cannot inspect EXE dependencies' }
  if ($imports | Where-Object { $_ -match '(libssl|libcrypto|libwinpthread|libgcc|libstdc\+\+|vcruntime|msvcp)' }) {
    throw "Portable EXE still imports a compiler or OpenSSL runtime library: $($imports -join ', ')"
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
foreach ($license in @('LICENSE-ImGui.txt', 'LICENSE-Inter.txt')) {
  Copy-Item -LiteralPath (Join-Path (Split-Path $built) $license) -Destination $output -Force
}
Get-ChildItem -LiteralPath $output | Select-Object Name, Length
