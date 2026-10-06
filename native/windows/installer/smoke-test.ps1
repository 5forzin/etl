param([Parameter(Mandatory)][string]$InstallerPath)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true') { throw 'Installer smoke tests run only in a disposable CI runner' }
$etlRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$etlTestRoot = [IO.Path]::GetFullPath((Join-Path $etlRoot 'build/installer-smoke'))
$etlInstallDirectory = Join-Path $etlTestRoot 'app'
$etlUninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{53C72D03-2FB4-47B7-B02A-661EB9A5B56E}_is1'
$etlProfileDirectory = Join-Path $env:APPDATA 'ETL'
$etlSettingsPath = Join-Path $etlProfileDirectory 'settings.ini'
$etlDesktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'ETL.lnk'
$etlMenuShortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'ETL/ETL.lnk'
if ((Test-Path -LiteralPath $etlProfileDirectory) -or (Test-Path -LiteralPath $etlUninstallKey) -or
    (Test-Path -LiteralPath $etlDesktopShortcut) -or (Test-Path -LiteralPath $etlMenuShortcut)) {
  throw 'Refusing installer tests against an existing ETL profile or installation'
}
New-Item -ItemType Directory -Path $etlTestRoot,$etlProfileDirectory -Force | Out-Null
[IO.File]::WriteAllText($etlSettingsPath,"[client]`nserver=profile-sentinel.example`ntoken_protected=profile-sentinel`n")
$etlProfileHash = (Get-FileHash -LiteralPath $etlSettingsPath -Algorithm SHA256).Hash
function Assert-EtlProfile {
  if ((Get-FileHash -LiteralPath $etlSettingsPath -Algorithm SHA256).Hash -ne $etlProfileHash) { throw 'Installer changed user settings' }
}
function Install-EtlPackage([string]$LogName) {
  $etlSetupProcess = Start-Process -FilePath (Resolve-Path $InstallerPath).Path -ArgumentList @(
    '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-', '/TASKS="desktopicon"',
    ('/DIR="'+$etlInstallDirectory+'"'),('/LOG="'+(Join-Path $etlTestRoot $LogName)+'"')
  ) -WindowStyle Hidden -PassThru -Wait
  if ($etlSetupProcess.ExitCode -ne 0) { throw "Installation failed: $($etlSetupProcess.ExitCode)" }
  Assert-EtlProfile
}
Install-EtlPackage 'install.log'
$etlVersion = (Get-Content -LiteralPath (Join-Path $etlRoot 'package.json') -Raw | ConvertFrom-Json).version
$etlInstalledExe = Join-Path $etlInstallDirectory 'etl-client.exe'
if ((Get-Item -LiteralPath $etlInstalledExe).VersionInfo.ProductVersion -ne $etlVersion) { throw 'Installed executable version mismatch' }
$etlInstalledInfo = Get-ItemProperty -LiteralPath $etlUninstallKey
if ($etlInstalledInfo.DisplayVersion -ne $etlVersion -or $etlInstalledInfo.InstallLocation.TrimEnd('\') -ne $etlInstallDirectory) {
  throw 'Per-user uninstall registration is incorrect'
}
$etlShell = New-Object -ComObject WScript.Shell
foreach ($etlShortcutPath in @($etlDesktopShortcut,$etlMenuShortcut)) {
  if (-not (Test-Path -LiteralPath $etlShortcutPath)) { throw "Missing shortcut: $etlShortcutPath" }
  if ($etlShell.CreateShortcut($etlShortcutPath).TargetPath -ne $etlInstalledExe) { throw 'Shortcut target mismatch' }
}
& $etlInstalledExe '--self-test-ui' (Join-Path $etlTestRoot 'installed-preview.bmp')
if ($LASTEXITCODE -ne 0) { throw 'Installed client did not render' }
Install-EtlPackage 'repair.log'
if (@(Get-ChildItem -LiteralPath $etlInstallDirectory -Filter 'unins*.exe').Count -ne 1) { throw 'Repair duplicated the uninstaller' }
$etlUninstallerPath = Join-Path $etlInstallDirectory 'unins000.exe'
$etlUninstaller = Start-Process -FilePath $etlUninstallerPath -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',
  ('/LOG="'+(Join-Path $etlTestRoot 'uninstall.log')+'"')) -WindowStyle Hidden -PassThru -Wait
if ($etlUninstaller.ExitCode -ne 0) { throw "Uninstall failed: $($etlUninstaller.ExitCode)" }
Assert-EtlProfile
foreach ($etlRemovedPath in @($etlInstalledExe,$etlUninstallKey,$etlDesktopShortcut,$etlMenuShortcut)) {
  if (Test-Path -LiteralPath $etlRemovedPath) { throw "Uninstall left an installed resource: $etlRemovedPath" }
}
Write-Output 'Installer checks passed: install, shortcuts, rendering, repair, uninstall and preserved profile.'
