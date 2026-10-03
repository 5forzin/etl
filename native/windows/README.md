# Windows client

The desktop client uses Dear ImGui, DirectX 11 and an embedded Inter font. It
opens a local proxy for SOCKS5, HTTP CONNECT and ordinary HTTP requests. It
forwards TCP through the same ETL v1 server as the Node client.

## Use

Run `etl-client.exe`, enter the server and token, then Connect. Ports, backup,
timeout and CA are under Options. The token input is masked. A saved token remains
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

Each server attempt has a default one-second deadline covering DNS, TCP, verified
TLS and authentication. New connections may use a backup with its own token.
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

## Verify

~~~powershell
$env:ETL_NATIVE_CLIENT = (Resolve-Path dist/windows-portable/etl-client.exe).Path
$env:ETL_OPENSSL = 'C:\Program Files\Git\usr\bin\openssl.exe'
node --test test/native-client.test.js
~~~

The suite checks DPAPI, SOCKS/HTTP relaying, failover, certificate rejection,
IPv6, negotiation and idle deadlines, argument validation and DirectX rendering.
`--self-test-ui OUTPUT.bmp` creates a hidden preview using default settings;
it neither loads a user profile nor opens a proxy. CI also saves this preview.

Headless mode takes `--server`, `--server-port`, `--port`, `--token-file`,
`--ca`, `--fallback-server`, `--fallback-port`, `--fallback-token-file` and
`--connect-timeout-ms`. It additionally accepts `--handshake-timeout-ms`
(1–65535; default 10000) and `--idle-timeout-ms` (1–600000; default 120000).
Headless mode never renders the desktop.

See the [design notes and Figma sketch](../../docs/desktop-design.md).
