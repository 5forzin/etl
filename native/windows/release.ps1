param(
  [string]$PackageDirectory = 'dist/windows-portable',
  [string]$InstallerDirectory = 'dist/windows-installer',
  [string]$OutputDirectory = '',
  [string]$NotesPath = ''
)
# Assembles the files of a GitHub release from a tested portable package and
# installer: the standalone client, the portable zip, the installer, the
# dependency licenses and one SHA256SUMS covering all of them. With -NotesPath
# it also writes the release notes: the version's CHANGELOG section.
$ErrorActionPreference = 'Stop'
$etlRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
function Resolve-EtlPath([string]$Path) {
  if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
  return [IO.Path]::GetFullPath((Join-Path $etlRoot $Path))
}
$etlVersion = (Get-Content -LiteralPath (Join-Path $etlRoot 'package.json') -Raw | ConvertFrom-Json).version
if ($etlVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Releases require a numeric three-part version' }
$etlPackage = Resolve-EtlPath $PackageDirectory
$etlInstaller = Join-Path (Resolve-EtlPath $InstallerDirectory) "ETL-Setup-$etlVersion-x64.exe"
$etlOutput = Resolve-EtlPath $(if ($OutputDirectory) { $OutputDirectory } else { "dist/release-$etlVersion" })
$etlLicenses = @('LICENSE-ImGui.txt', 'LICENSE-Inter.txt', 'LICENSE-JSON.txt', 'LICENSE-OpenSSL.txt')
foreach ($etlFile in @('etl-client.exe', 'SHA256SUMS') + $etlLicenses) {
  if (-not (Test-Path -LiteralPath (Join-Path $etlPackage $etlFile) -PathType Leaf)) { throw "Missing package file: $etlFile" }
}
if (-not (Test-Path -LiteralPath $etlInstaller -PathType Leaf)) { throw "Missing installer: $etlInstaller" }
$etlExecutable = Join-Path $etlPackage 'etl-client.exe'
if ((Get-Item -LiteralPath $etlExecutable).VersionInfo.ProductVersion -ne $etlVersion) {
  throw 'Executable version differs from package.json'
}
$etlHash = (Get-FileHash -LiteralPath $etlExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
if ((Get-Content -LiteralPath (Join-Path $etlPackage 'SHA256SUMS')) -notcontains "$etlHash  etl-client.exe") {
  throw 'Portable package checksum mismatch; run package.ps1 again'
}
if (Test-Path -LiteralPath $etlOutput) { Remove-Item -LiteralPath $etlOutput -Recurse -Force }
New-Item -ItemType Directory -Force -Path $etlOutput | Out-Null
$etlZip = Join-Path $etlOutput "ETL-$etlVersion-windows-x64-portable.zip"
$etlZipped = @('etl-client.exe') + $etlLicenses + @('SHA256SUMS') | ForEach-Object { Join-Path $etlPackage $_ }
Compress-Archive -LiteralPath $etlZipped -DestinationPath $etlZip -CompressionLevel Optimal
Copy-Item -LiteralPath $etlExecutable -Destination $etlOutput
Copy-Item -LiteralPath $etlInstaller -Destination $etlOutput
foreach ($etlLicense in $etlLicenses) { Copy-Item -LiteralPath (Join-Path $etlPackage $etlLicense) -Destination $etlOutput }
$etlAssets = @("ETL-$etlVersion-windows-x64-portable.zip", 'etl-client.exe', "ETL-Setup-$etlVersion-x64.exe") + $etlLicenses
$etlSums = foreach ($etlAsset in $etlAssets) {
  "$((Get-FileHash -LiteralPath (Join-Path $etlOutput $etlAsset) -Algorithm SHA256).Hash.ToLowerInvariant())  $etlAsset"
}
[IO.File]::WriteAllText((Join-Path $etlOutput 'SHA256SUMS'), (($etlSums -join "`n") + "`n"))
if ($NotesPath) {
  $etlLines = @(Get-Content -LiteralPath (Join-Path $etlRoot 'CHANGELOG.md'))
  $etlStart = -1
  for ($i = 0; $i -lt $etlLines.Count -and $etlStart -lt 0; $i++) {
    if ($etlLines[$i] -match "^## $([regex]::Escape($etlVersion))( |$)") { $etlStart = $i }
  }
  if ($etlStart -lt 0) { throw "CHANGELOG.md has no section for $etlVersion" }
  $etlEnd = $etlLines.Count
  for ($i = $etlStart + 1; $i -lt $etlLines.Count; $i++) {
    if ($etlLines[$i] -match '^## ') { $etlEnd = $i; break }
  }
  # GitHub renders every newline in release notes, so wrapped CHANGELOG bullets
  # are joined back into one line each.
  $etlJoined = [Collections.Generic.List[string]]::new()
  foreach ($etlLine in $etlLines[($etlStart + 1)..($etlEnd - 1)]) {
    if ($etlLine -match '^\s+\S' -and $etlJoined.Count -and $etlJoined[$etlJoined.Count - 1]) {
      $etlJoined[$etlJoined.Count - 1] += ' ' + $etlLine.Trim()
    } else { $etlJoined.Add($etlLine.TrimEnd()) }
  }
  $etlSection = ($etlJoined -join "`n").Trim()
  $etlNotes = @(
    $etlSection, '',
    "Download **ETL-Setup-$etlVersion-x64.exe** for the installer, **etl-client.exe** for the standalone portable client, or **ETL-$etlVersion-windows-x64-portable.zip** for the portable client with dependency licenses. Saved servers and encrypted credentials are preserved. Checksums are in **SHA256SUMS**."
  ) -join "`n"
  [IO.File]::WriteAllText((Resolve-EtlPath $NotesPath), $etlNotes + "`n")
}
Get-ChildItem -LiteralPath $etlOutput | Select-Object Name, Length
