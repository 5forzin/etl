#ifndef AppVersion
  #error AppVersion is required; use build.ps1
#endif
#ifndef PackageDir
  #error PackageDir is required; use build.ps1
#endif
#ifndef BrandDir
  #error BrandDir is required; use build.ps1
#endif
#ifndef OutputPath
  #error OutputPath is required; use build.ps1
#endif

[Setup]
AppId={{53C72D03-2FB4-47B7-B02A-661EB9A5B56E}
AppName=ETL
AppVersion={#AppVersion}
AppPublisher=Anthony Sforzin
AppPublisherURL=https://github.com/5forzin/etl
AppSupportURL=https://github.com/5forzin/etl/issues
AppUpdatesURL=https://github.com/5forzin/etl/releases
DefaultDirName={localappdata}\Programs\ETL
DefaultGroupName=ETL
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputPath}
OutputBaseFilename=ETL-Setup-{#AppVersion}-x64
SetupIconFile={#BrandDir}\etl.ico
UninstallDisplayIcon={app}\etl-client.exe
UninstallDisplayName=ETL
VersionInfoVersion={#AppVersion}.0
VersionInfoDescription=ETL installer
WizardStyle=modern dynamic windows11 hidebevels
WizardSizePercent=100
WizardSmallImageFile={#BrandDir}\wizard-black.png
WizardSmallImageFileDynamicDark={#BrandDir}\wizard-white.png
WizardSmallImageBackColor=$FFFFFF
WizardSmallImageBackColorDynamicDark=$202020
WizardImageFile={#BrandDir}\wizard-banner-black.png
WizardImageFileDynamicDark={#BrandDir}\wizard-banner-white.png
WizardImageBackColor=$FFFFFF
WizardImageBackColorDynamicDark=$202020
DisableWelcomePage=yes
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
AllowNoIcons=yes
CloseApplications=yes
CloseApplicationsFilter=etl-client.exe
RestartApplications=no
Compression=lzma2
SolidCompression=yes
Uninstallable=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
SetupWindowTitle=ETL
WizardSelectTasks=Shortcuts
SelectTasksDesc=
SelectTasksLabel2=
WizardInstalling=Installing ETL
InstallingLabel=
FinishedHeadingLabel=ETL is installed
FinishedLabelNoIcons=
FinishedLabel=

[Tasks]
Name: "desktopicon"; Description: "Desktop shortcut"; Flags: checkedonce

[Files]
Source: "{#PackageDir}\etl-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\LICENSE-ImGui.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\LICENSE-Inter.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\LICENSE-OpenSSL.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\SHA256SUMS"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ETL"; Filename: "{app}\etl-client.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\ETL"; Filename: "{app}\etl-client.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\etl-client.exe"; Description: "Open ETL"; Flags: nowait postinstall skipifsilent

; User profiles and encrypted tokens live outside {app}. No profile cleanup is
; registered, so upgrades, repairs and uninstall preserve them.
