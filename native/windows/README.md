# Windows client

The desktop client uses Dear ImGui, DirectX 11 and an embedded Inter font. It
opens a local proxy for SOCKS5, HTTP CONNECT and ordinary HTTP requests. It
forwards TCP through the same ETL v1 server as the Node client.

## Use

Download `ETL-Setup-VERSION-x64.exe` from [releases](https://github.com/5forzin/etl/releases).
It installs under `%LOCALAPPDATA%\Programs\ETL` for the current Windows user,
adds a Start menu shortcut and offers a Desktop shortcut. No administrator
account is required. The installer follows the Windows light or dark appearance.
It can also update an existing copy in that folder. Exit ETL from the tray before
updating or uninstalling it. Saved settings and DPAPI tokens remain in
`%APPDATA%\ETL` after uninstall. Remove that folder yourself if you want to reset
the profile.

The portable `etl-client.exe` remains available as a separate download.

Run `etl-client.exe`, enter the server and token, then click the power button.
The borderless window is 360 pixels wide, with a draggable header and custom
minimize and close controls. Options expands ports, backup, timeout and CA below
the main controls. The window grows and shrinks smoothly to fit, without scrollbars.
The token input is masked. A saved token remains
in use when the field is blank; entering a new token replaces it. Leaving the
backup host empty disables failover. A new backup with no token uses the primary
credential; an existing saved backup token is retained when its field is blank.

“Proxy active” means `127.0.0.1:<local port>` is listening. It does not mean the
remote host has been authenticated; that happens for each application connection.
The counters show bytes relayed since the last local start. Closing the window
keeps the client in the tray. Use the tray's Exit action to stop it.

~~~powershell
curl.exe --proxy socks5h://127.0.0.1:1080 https://example.com
curl.exe --proxy http://127.0.0.1:1080 https://example.com
~~~

Settings live in `%APPDATA%\ETL\settings.ini`. Tokens are encrypted with
current-user DPAPI. Legacy token-file settings migrate when the file is readable.
Tokens are not included in the executable or release. An existing client profile
is loaded but does not start automatically when the desktop opens.

Each server attempt has a default five-second deadline covering DNS, TCP, verified
TLS and authentication. New connections may use a backup with its own token.
The backup is checked in the background at startup and every 30 seconds after
each check. It receives traffic only after verified TLS and ETL authentication
succeed. A failed check or connection disables it until a later check succeeds.
Checks send no destination or application data and do not block primary traffic.
Active streams never move between servers. TLS verification stays enabled.

## Build a portable executable

MSYS2 UCRT64 with GCC, OpenSSL, CMake and Ninja:

~~~powershell
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
cmake -S native/windows -B build/windows-portable -G Ninja -DCMAKE_BUILD_TYPE=Release -DETL_PORTABLE=ON
cmake --build build/windows-portable
./native/windows/package.ps1 -Portable
~~~

MSVC with Visual Studio's C++ desktop workload and vcpkg:

~~~powershell
git clone https://github.com/microsoft/vcpkg.git build/vcpkg
git -C build/vcpkg checkout da2be01c400dd3ed102c1198752ef44c76aabe37
./build/vcpkg/bootstrap-vcpkg.bat -disableMetrics
./build/vcpkg/vcpkg.exe install openssl:x64-windows-static
$etlToolchain = (Resolve-Path build/vcpkg/scripts/buildsystems/vcpkg.cmake).Path
cmake -S native/windows -B build/windows-portable -A x64 "-DCMAKE_TOOLCHAIN_FILE=$etlToolchain" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DETL_PORTABLE=ON
cmake --build build/windows-portable --config Release
./native/windows/package.ps1 -Portable
~~~

Use separate build directories when switching compilers. Dear ImGui is fetched at
the commit pinned in CMake. Inter is checked into assets and embedded at build
time. The executable uses static OpenSSL/compiler libraries and Windows system
DLLs, including DirectX 11. It requires no installed font, Node or MSYS2 runtime.
If hardware rendering is unavailable it tries WARP software rendering.

The package script inspects DLL imports and writes `dist/windows-portable/`
with the EXE, SHA256SUMS and dependency licenses. Published downloads live under
[GitHub releases](https://github.com/5forzin/etl/releases); check which revision a
release contains. The build is not code-signed. Verify downloads with
`Get-FileHash ./etl-client.exe -Algorithm SHA256`.

If another copy is running, package to a separate folder:

~~~powershell
./native/windows/package.ps1 -Portable -OutputDirectory dist/windows-compact
~~~

## Verify

~~~powershell
$env:ETL_NATIVE_CLIENT = (Resolve-Path dist/windows-portable/etl-client.exe).Path
$env:ETL_OPENSSL = 'C:\Program Files\Git\usr\bin\openssl.exe'
node --test test/native-client.test.js test/fallback.test.js
~~~

The suite checks DPAPI, SOCKS/HTTP relaying, failover, certificate rejection,
IPv6, negotiation and idle deadlines, argument validation and DirectX rendering.
`--self-test-ui OUTPUT.bmp` creates a hidden preview using default settings;
it neither loads a user profile nor opens a proxy. CI also saves this preview.
`--self-test-ui-options OUTPUT.bmp` checks animated expansion and collapse, then
captures expanded Options. `--self-test-ui-error OUTPUT.bmp` captures a wrapped
error. Preview modes use a fixed animation step and check that the native caption
is absent and header dragging leaves window controls clickable.

Headless mode takes `--server`, `--server-port`, `--port`, `--token-file`,
`--ca`, `--fallback-server`, `--fallback-port`, `--fallback-token-file` and
`--connect-timeout-ms`. It additionally accepts `--handshake-timeout-ms`
(1–65535; default 10000) and `--idle-timeout-ms` (1–600000; default 120000).
`--fallback-check-interval-ms` sets the backup check interval (100–60000;
default 30000). Headless mode never renders the desktop.

See the [design notes and Figma sketch](../../docs/desktop-design.md).

## Build the installer

Build and package the portable client first. With [Inno Setup](https://jrsoftware.org/isdl.php)
6.7 or later installed:

~~~powershell
./native/windows/installer/build.ps1
~~~

Pass `-CompilerPath PATH` if `ISCC.exe` is outside the usual installation folders.
`-PackageDirectory` selects a portable package; `-OutputDirectory` defaults to
`dist/windows-installer`. Paths are resolved from the repository root. The script
checks the executable version and package checksum before compiling.

The installer is offline and contains only the client, dependency licenses and
the executable checksum. It includes no user settings or credentials, creates no
service and changes no system proxy. Windows Settings lists its per-user uninstall
entry. Silent deployment uses:

~~~powershell
./ETL-Setup-VERSION-x64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
~~~

Silent installs do not launch ETL. `/TASKS="desktopicon"` selects the Desktop
shortcut; `/TASKS=""` omits it. The same App ID is used for upgrades and repairs.

CI builds the installer with the runner's Inno Setup compiler. It tests install,
repair, shortcuts, rendering, uninstall registration and profile preservation on
a disposable Windows runner. The installer and portable package are unsigned.

Logo sources and exports live in [assets/brand](../../assets/brand/README.md).
