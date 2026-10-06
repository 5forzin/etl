param(
  [string]$PackageDirectory = 'dist/windows-portable',
  [string]$OutputDirectory = 'dist/windows-installer',
  [string]$CompilerPath = ''
)
$ErrorActionPreference = 'Stop'
$etlRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
function Resolve-EtlBuildPath([string]$Path) {
  if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
  return [IO.Path]::GetFullPath((Join-Path $etlRoot $Path))
}
$etlPackage = Resolve-EtlBuildPath $PackageDirectory
$etlOutput = Resolve-EtlBuildPath $OutputDirectory
$etlVersion = (Get-Content -LiteralPath (Join-Path $etlRoot 'package.json') -Raw | ConvertFrom-Json).version
if ($etlVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Installer builds require a numeric three-part version' }
foreach ($etlFile in @('etl-client.exe','SHA256SUMS','LICENSE-ImGui.txt','LICENSE-Inter.txt','LICENSE-OpenSSL.txt')) {
  if (-not (Test-Path -LiteralPath (Join-Path $etlPackage $etlFile) -PathType Leaf)) { throw "Missing package file: $etlFile" }
}
$etlExecutable = Join-Path $etlPackage 'etl-client.exe'
$etlHash = (Get-FileHash -LiteralPath $etlExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
if ((Get-Content -LiteralPath (Join-Path $etlPackage 'SHA256SUMS')) -notcontains "$etlHash  etl-client.exe") {
  throw 'Portable package checksum mismatch; run package.ps1 again'
}
if ((Get-Item -LiteralPath $etlExecutable).VersionInfo.ProductVersion -ne $etlVersion) {
  throw 'Executable version differs from package.json; rebuild the client first'
}
if (-not $CompilerPath) {
  $etlInstalledCompiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  $etlCandidates = @(
    $(if ($etlInstalledCompiler) { $etlInstalledCompiler.Source }),
    $(Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6/ISCC.exe'),
    $(Join-Path $env:ProgramFiles 'Inno Setup 7/ISCC.exe'),
    $(Join-Path $env:LOCALAPPDATA 'Programs/Inno Setup 6/ISCC.exe'),
    $(Join-Path $env:LOCALAPPDATA 'Programs/Inno Setup 7/ISCC.exe')
  )
  $CompilerPath = $etlCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
if (-not $CompilerPath -or -not (Test-Path -LiteralPath $CompilerPath)) {
  throw 'Inno Setup 6.7 or later is required. Pass -CompilerPath to its ISCC.exe.'
}
$etlCompilerVersion = (Get-Item -LiteralPath $CompilerPath).VersionInfo.FileVersion
if ([version]$etlCompilerVersion -lt [version]'6.7.0') { throw 'Inno Setup 6.7 or later is required' }
New-Item -ItemType Directory -Path $etlOutput -Force | Out-Null
& $CompilerPath '/Qp' "/DAppVersion=$etlVersion" "/DPackageDir=$etlPackage" "/DBrandDir=$(Join-Path $etlRoot 'assets/brand')" "/DOutputPath=$etlOutput" (Join-Path $PSScriptRoot 'etl.iss')
if ($LASTEXITCODE -ne 0) { throw "Installer compiler failed: $LASTEXITCODE" }
$etlInstaller = Join-Path $etlOutput "ETL-Setup-$etlVersion-x64.exe"
if (-not (Test-Path -LiteralPath $etlInstaller)) { throw 'Installer compiler produced no output' }
$etlInstallerHash = (Get-FileHash -LiteralPath $etlInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $etlOutput 'SHA256SUMS'), "$etlInstallerHash  $([IO.Path]::GetFileName($etlInstaller))`n")
[PSCustomObject]@{Installer=$etlInstaller; Version=$etlVersion; SHA256=$etlInstallerHash}
