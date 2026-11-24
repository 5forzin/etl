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

ETL checks the latest stable GitHub Release at startup and once an hour while
running. When a newer version is available, choose Update or Later in the app.
Later dismisses that version for the current session. Settings includes a manual
Check for updates action. A minimized or hidden client also shows a tray notification.

Updates download over verified HTTPS and must match the asset's GitHub SHA-256
digest and size before installation. ETL stops its proxy and restarts after the
download; active connections close. Installed copies run the per-user installer
in their existing folder. Portable copies replace only their executable, with
rollback if the copy fails. Saved settings and DPAPI tokens remain in `%APPDATA%\ETL`.
Network failures leave the current client usable and can be retried.

To publish an update, increase `package.json`'s version, add its `CHANGELOG.md`
section and push the tag `vVERSION`. The Release workflow builds and tests the
client and installer on a clean Windows runner and opens a **draft** release named
`ETL VERSION` with every download, the aggregated `SHA256SUMS` and the changelog
section as notes (`native/windows/release.ps1` assembles the same files locally).
Test those exact files, then publish the draft and mark it as Latest; only then
do clients offer the update. GitHub supplies the asset digests on upload. Drafts,
prereleases, older versions and assets without a valid digest are not installed.
The first release containing this updater must be installed manually by users of
earlier versions.

Run `etl-client.exe`, enter the server and token in Settings, then choose a mode.

- **Proxy only** opens the local listener. Only applications configured to use
  `127.0.0.1:<local port>` go through ETL.
- **Selective** routes only the connections that the network blocks for Twingate.
  When `Twingate.Service.exe` tries to reach one of its relays on a port the
  network drops (the attempt sits in SYN-SENT; ports 53, 80 and 443 are never
  touched), ETL adds a /32 route for that relay to the TUN adapter and the next
  retransmission goes through ETL. DNS, the default route and every other
  connection stay on the normal network. The app shows how many relay addresses
  it routed. Use it when Twingate's private resources time out on a restrictive
  network. Selective fails open: if the ETL server stops answering three checks
  in a row, it withdraws its relay routes (Twingate falls back to the normal
  network), shows "Reconnecting" and resumes once the server answers again. Each
  failed check is logged as `health-server-failed` with its stage and duration.
- **Full mode** routes the whole PC through the TUN adapter. It heals itself: when
  the tunnel is lost (three failed checks, or the engine exiting) it restores the
  normal connection at once, shows "Reconnecting" with an amber dot, checks the
  server after 2, 4, 8 and 16 seconds and then every 30 seconds, and rebuilds the
  tunnel as soon as the server answers. Only Disconnect, or a tunnel that cannot
  be rebuilt three times in a row, ends the session.

Selective and Full start a separate elevated worker; the desktop and browser
keep normal user permissions. Both use the selected server; the primary profile's
backup remains saved for Proxy only. They authenticate before changing routes and
restore the normal connection after Disconnect, Exit or a desktop crash. While
they run they follow the physical network every two seconds: after a switch
between Wi-Fi and cable, a new access point or a resume from sleep they re-pin
the server route on the new gateway (the new route goes in before the old one is
removed), move the weak host setting to the new interface and re-arm the
restoration guard for it. A host route that Windows dropped on reconnection is
put back. Closing the window hides it in the tray and keeps the selected mode
running. Opening ETL again shows the window that is already running instead of
starting a second copy.

The borderless window is 400 logical pixels wide, with a draggable header and
custom minimize and close controls. It is DPI aware (per monitor): layout, icons
and text are drawn at the display scale (600 sharp pixels at 150%) instead of
being stretched, and moving the window to a monitor with another scale redraws
it there. Settings contains server credentials, ports, backup, timeout and CA,
plus Copy diagnostics, which puts the version, Windows build, mode, server,
tunnel state, default route, display scale and the latest runtime log lines on
the clipboard (never tokens). Save persists edits without starting a connection.
The mode selector, hover states, page transitions and window height animate
smoothly, respecting Windows' reduced-animation preference.

Open browser opens a separate Edge or Chrome session with
`--proxy-server=socks5://127.0.0.1:<local port>` and remote hostname resolution.
It prefers the default browser when that is Edge or Chrome. Profiles live under
`%LOCALAPPDATA%\ETL\Browser`, separately for each browser and proxy port.
If disconnected, this action starts Proxy only or reuses an existing local SOCKS5
listener. It does not change the system proxy or normal browser profile.

Servers lists the primary profile and registered agents. Add server generates a
Windows or Linux x64 executable with a single-use pairing code. The templates
are embedded in the app, so exporting needs no compiler or additional download.
Agents appear automatically after registration. Selecting one preserves the
primary and backup profile. Agent credentials are cached with current-user DPAPI;
each connection verifies that agent's own certificate and hostname. See
[agents](../../docs/agents.md) for server requirements and execution.

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
TLS and authentication. A connection sends its destination in the same TLS record
as the authentication frame and disables Nagle's algorithm, so setup takes three
round trips: TCP, TLS, then authentication together with the destination. Before
0.8, authentication and destination took one round trip each and Nagle's
algorithm could hold a small frame for another. Measured through the production
server, a new HTTPS request went from about 2.0 seconds to between 1.1 and 1.4 seconds.
New connections may use a backup with its own token.
The backup is checked in the background at startup and every 30 seconds after
each check. It receives traffic only after verified TLS and ETL authentication
succeed. A failed check or connection disables it until a later check succeeds.
Checks send no destination or application data and do not block primary traffic.
Active streams never move between servers. TLS verification stays enabled.

## Build a portable executable

Install Go 1.25 or later and make `go` available on PATH. CMake compiles static
Windows and Linux x64 agent templates and embeds both in the desktop executable.
CI uses Go 1.27.3. Override its path with `-DETL_GO_EXECUTABLE=PATH` if needed.

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
captures Settings. `--self-test-ui-error OUTPUT.bmp` captures a wrapped
error. Preview modes use a fixed animation step and check that the native caption
is absent and header dragging leaves window controls clickable.

`--self-test-ui-update`, `--self-test-ui-downloading` and
`--self-test-ui-update-error` capture the update confirmation, progress and retry
states. Pass an output BMP path to each. These previews do not contact GitHub.
`ctest --test-dir build/windows-portable -C Release --output-on-failure` checks
release parsing, version ordering, checksums, portable rollback, browser arguments
and the desktop worker lifecycle. Worker tests exercise traffic reporting,
cancellation, errors and parent death without UAC or network route changes.

`--self-test-ui-full`, `--self-test-ui-full-active`, `--self-test-ui-full-dns`,
`--self-test-ui-full-reconnecting`, `--self-test-ui-selective`,
`--self-test-ui-selective-paused`, `--self-test-ui-connecting` and
`--self-test-ui-stopping` capture the mode selector and connection states.
Previews render at 100% scale on any display; `--self-test-ui-scaled` renders
the main page at 150% and the suite checks that it is 600 pixels wide and scaled
as a whole.
Previews are 32-bit bitmaps with straight alpha: the corners outside the rounded
window outline are transparent and the outline is anti-aliased, as on screen.
`--self-test-ui-active` captures the local proxy's traffic counters. These fixtures
render synthetic test data without starting a connection or loading saved tokens.
Preview animations are deterministic and independent of the host's animation
preference. `--self-test-ui-reduced` checks that Settings opens and closes
immediately when reduced motion is requested.

`--self-test-ui-servers-many` previews a scrolling list with long names and
addresses; `--self-test-ui-servers-empty` checks a profile without agents.
`--self-test-ui-long-server` checks the connected layout with a long hostname
and large traffic counters.

Headless mode takes `--server`, `--server-port`, `--port`, `--token-file`,
`--ca`, `--servername`, `--fallback-server`, `--fallback-port`, `--fallback-token-file` and
`--connect-timeout-ms`. It additionally accepts `--handshake-timeout-ms`
(1–65535; default 10000) and `--idle-timeout-ms` (1–600000; default 120000).
`--fallback-check-interval-ms` sets the backup check interval (100–60000;
default 30000). Headless mode never renders the desktop.

Add `--vpn 1` to headless mode from an elevated terminal to route traffic
through the TUN adapter. ETL authenticates before changing routes. Three seconds
after connecting, and then every four seconds, Full mode checks that the routes
still point at the adapter and relays a DNS exchange over TCP through the
tunnel, trying Cloudflare and Google at the same time with four seconds each.
Three consecutive failed checks restore the normal connection (one every two
seconds while failing); an engine exit restores it immediately. The client then
exits with code 5, unless `--vpn-reconnect 1` is given: then it keeps running,
reconnects the way the desktop does and prints each loss and restoration.
Physical default routes and DNS settings remain unchanged, and restoration
removes the TUN routes and flushes cached synthetic DNS answers. Routes are
created and deleted through the IP Helper API, never `route.exe`. Mapped-DNS
answers use `198.19.0.0/16`, inside the benchmarking range `198.18.0.0/15`
that is never routed on the internet (until 0.7 they used `100.64.0.0/10`,
which collides with CGNAT, Tailscale and Twingate addresses).

The worker, the guard and headless runs log to `%LOCALAPPDATA%\ETL\runtime\error.log`
and `guard.log`. Each line starts with the local time and the process id; a log
past 512 KiB moves to `error.log.1` (or `guard.log.1`), replacing the older copy.

Some services, Twingate among them, bind their sockets to the physical adapter's
address. Under Windows' default strong host model such packets never leave
through another interface, and the check applies to the interface that owns the
source address. Measured with Twingate on a network that blocks its relay ports:
weak host send and receive on the TUN adapter alone left every relay attempt in
SYN-SENT; also allowing weak host sends on the physical interface connected them
in both Selective and Full mode (weak host receive there made no difference).
So while Selective or Full mode runs, the TUN adapter sends and receives for other
addresses, and the interface that carries the default route allows weak host
sends. That change uses `store=active` and is undone on Disconnect, on a tunnel
failure, by the restoration guard after a crash, and by a reboot. If weak host
sends were already enabled, ETL leaves them alone.

`--vpn-selective 1` (with `--vpn 1`) selects the Selective layout in headless
mode and prints each relay address it routes and each pause or resume. It only
exits (code 5) when the tunnel engine exits. It cannot be combined with
`--vpn-scope` or `--vpn-reconnect`.

The same check also sends a UDP query to the engine's mapped DNS. That result is
informational: other VPN clients (Twingate, for example) block UDP port 53 outside
their own adapter, which leaves the tunnel working while the system resolver can
not use ETL's DNS. ETL then keeps running, logs `dns-bypassed` in
`%LOCALAPPDATA%\ETL\runtime\error.log` and shows "DNS is not reaching the tunnel".
Name lookups in that situation are answered by the other client's resolver
instead of the ETL server.

`ctest` also checks fragmented, invalid and stalled connectivity probe replies.
To test real network restoration, stop any active ETL VPN and run the following
from an elevated PowerShell terminal with a private token file:

~~~powershell
./native/windows/test_vpn_recovery.ps1 -ExecutablePath ./build/windows-vpn/etl-client.exe `
  -Server etl.example.com -TokenPath C:/private/etl.token -OutputPath ./build/vpn-recovery/results.json
~~~

The integration test checks authentication failure, a temporary firewall rule
that blocks only the test client's server connection, engine exit and parent
crash. It verifies normal HTTPS access and unchanged physical DNS after each.

See the [design notes](../../docs/desktop-design.md).

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
