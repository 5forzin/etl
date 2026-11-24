# Changelog

## 0.8.0 (2026-11-24)

- **Faster connections.** Every new connection used to wait for the server to
  accept its token before naming the destination, and Nagle's algorithm could
  hold the small setup frames back for another round trip. Clients now send the
  destination in the same TLS record as the token and disable Nagle on the
  tunnel socket (the server also does, after its next deployment). Measured
  through the production server, a new HTTPS request went from about 2.0 seconds
  to between 1.1 and 1.4 seconds. Servers already read frames in order, so
  older servers benefit too.
- **Full mode reconnects by itself.** A lost tunnel still restores the normal
  connection at once, but the session no longer ends: the app shows
  "Reconnecting" with an amber dot, checks the server after 2, 4, 8 and 16
  seconds and then every 30 seconds, and rebuilds the tunnel when the server
  answers. Tested live by blocking the server: the normal connection came back
  in 8 seconds and the tunnel in under 10 seconds after unblocking.
- **Network changes no longer break a session.** Selective and Full mode follow
  the physical network every two seconds. After a switch between Wi-Fi and
  cable, a new access point or a resume from sleep they re-pin the server route
  on the new gateway (before removing the old one), move the weak host setting
  to the new interface and re-arm the restoration guard for it. A host route
  that Windows drops on reconnection is put back within two seconds.
- **Sharp on high-DPI displays.** The window is per-monitor DPI aware: at 150%
  it is drawn at 600 sharp pixels instead of being stretched, and it rescales
  when moved to another monitor.
- **Copy diagnostics** in Settings puts the version, Windows build, mode,
  server, tunnel state, default route, display scale and the latest runtime log
  lines on the clipboard. It never includes tokens.
- **One copy at a time.** Opening ETL while it runs shows the existing window
  instead of starting a second client that competes for the local port.
- Runtime logs carry the local time and process id on every line and rotate at
  512 KiB, so they no longer grow without limit.
- Routes are created and deleted through the IP Helper API instead of
  `route.exe`: faster starts (about 1.4 seconds to a working tunnel) and no
  silent deletion failures.
- Mapped-DNS answers move from `100.64.0.0/10`, which collides with CGNAT,
  Tailscale and Twingate addresses, to `198.19.0.0/16` in the benchmarking range.
- Headless Full mode accepts `--vpn-reconnect 1` to reconnect like the desktop.
- Node 26 support: IP addresses are no longer sent as TLS server names, which
  Node 26 rejects. This broke backup checks against IP backups; CI now tests
  Node 24 and 26.
- OpenSSL 4: certificate names use `SSL_set1_dnsname`, or `SSL_set1_ipaddr` for
  IP literals, instead of the deprecated `SSL_set1_host`.
- Releases are built on a clean CI runner from the version tag and opened as a
  draft for testing before publication.

## 0.7.1 (2026-11-23)

- Keep Selective mode running when the ETL server stops answering. It used Full
  mode's rule and ended with "Tunnel lost. Your normal connection has been
  restored." after three failed server checks, although Selective never takes
  the normal connection away; a short outage on the network was enough. Selective
  now fails open: it withdraws its relay routes, so Twingate uses the normal
  network (no worse than without ETL), shows "Reconnecting", and resumes routing
  by itself when the server answers. Only a tunnel engine exit ends it.
- Record why a server check failed (connect, TLS or authentication, failed or
  timed out, with the elapsed time) as `health-server-failed` in the runtime log.
  Selective checks use the configured connect timeout (default five seconds)
  instead of three seconds.
- Selective no longer pins a host route to the server; only Full mode needs it.
  This avoids a stale route when the gateway changes.

## 0.7.0 (2026-11-23)

- Add **Selective** mode to the Windows client, between Proxy only and Full mode.
  It routes only the connections that the network blocks for Twingate: when
  `Twingate.Service.exe` tries to reach a relay on a dropped port (the attempt
  sits in SYN-SENT; ports 53, 80 and 443 are never touched), ETL adds a /32 route
  for that relay to the TUN adapter and the next retransmission goes through ETL.
  DNS, the default route and all other traffic stay on the normal network. The
  app shows how many relay addresses it routed. This replaces the separate
  tunnel script previously needed for Twingate on restrictive networks.
- Make Full mode work with Twingate. Twingate binds its relay sockets to the
  physical adapter's address, and Windows only lets such packets leave through
  another interface when the interface that owns the address allows weak host
  sends. Measured on a network that blocks the relay ports: the TUN setting alone
  kept every attempt in SYN-SENT; allowing weak host sends on the physical
  interface connected them in both modes. Selective and Full mode now enable it
  while they run (store=active) and restore it on Disconnect, on a tunnel
  failure, from the restoration guard after a crash, and on reboot.
- Headless mode accepts `--vpn-selective 1` together with `--vpn 1`.
- The recovery integration test checks that physical weak host settings return
  to their original values in every scenario.

## 0.6.1 (2026-11-23)

- Keep Full mode connected when another VPN or firewall blocks UDP port 53.
  Twingate and similar clients block DNS outside their own adapter, so ETL's
  UDP check of its mapped DNS never got an answer and Full mode restored the
  normal connection a few seconds after connecting. A blocked mapped DNS is now
  reported in the app ("DNS is not reaching the tunnel") instead of ending the
  session; connections still go through ETL.
- Make tunnel failure detection tolerant of slow links. The relay check now
  allows four seconds on both resolvers at once (it previously allowed two, while
  opening an ETL session takes about two seconds on a slow network), waits three
  seconds after connecting, and needs three consecutive failures. An engine exit
  or a lost route still restores the connection immediately.
- Enable the weak host model on Full mode's own TUN adapter, so it may send and
  receive packets that carry another interface's address. The setting disappears
  with the adapter; no physical interface is changed. This alone does not yet
  let Twingate reach relays on a network that blocks their ports.
- Fix the window outline: the dark background no longer shows past the rounded
  grey border at the corners. The window is rendered with per-pixel alpha, so the
  border is the anti-aliased edge of the application on Windows 10 and 11.
- Build with the current MSYS2 OpenSSL 4, whose static libraries need `bcrypt`.

Desktop upgrades preserve saved settings and encrypted credentials.

## 0.6.0 (2026-10-29)

- Redesign the Windows desktop with a monochrome interface, an abstract logo,
  consistent borders and spacing, aligned controls, and smooth page transitions.
  Respect the Windows reduced-animation preference.
- Choose Proxy only or Full mode from the desktop. Full mode runs in a separate
  elevated worker and restores normal connectivity when the tunnel fails.
- Open an isolated Edge or Chrome session through the configured local proxy.
  Keep the normal browser profile and system proxy settings unchanged.
- Generate standalone Windows and Linux x64 agents with single-use pairing codes.
  Register and select servers from the desktop while preserving the primary and
  backup profiles. Agent hosts need a public IPv4 address and an inbound TCP port.
- Keep server lists compact and scroll long lists inside their rounded panel.
  Truncate long names and addresses, format large traffic totals, and align
  settings fields and header controls.
- Add native previews for long lists, long hostnames, large traffic totals and
  profiles without registered agents.

Existing proxy connections remain compatible. Update the primary Node server to
0.6.0 to enable agent enrollment and management. Desktop upgrades preserve saved
settings and encrypted credentials.

## 0.5.0 (2026-10-17)

- Add the ETL v2 protocol: a UDP session mode framed inside the same TLS 1.3
  connection on TCP 443. Clients authenticate with `{"v":2,"mode":"udp"}` and
  exchange datagrams as a JSON destination frame plus a length-prefixed payload
  of up to 1500 bytes. The server reuses the v1 destination policy per packet,
  keeps one outbound socket per destination with least-recently-used eviction
  and rejects blocked destinations without tearing the session down.
- Accept SOCKS5 UDP ASSOCIATE on the local fronts. The Node client and the
  Windows native client relay association datagrams through one v2 session, so
  UDP applications can use the same loopback proxy as TCP connections.
- Add an experimental system-wide VPN mode to the Windows client behind the
  `--headless --vpn 1 --vpn-scope IP` flags. Traffic to the scoped address is
  routed through a wintun adapter and the bundled hev-socks5-tunnel build into
  the existing SOCKS5 front, so every flow keeps its own TLS 1.3 connection.
  The server host route is pinned to the physical gateway, a watchdog process
  restores routes if the client dies, and scoped /32 routing was validated on
  networks with TLS interception. Full default-route takeover and the desktop
  toggle are not part of this release.
- Add a full-path benchmark (`scripts/bench.js`) recording single-flow
  throughput and setup latency for comparisons across releases.

Servers must upgrade to this release to accept v2 UDP sessions; v1 TCP flows
are unchanged, so older clients keep working during the upgrade.

## 0.4.0 (2026-10-14)

- Check for stable GitHub Releases at startup and once an hour in the Windows
  client. Offer Update and Later in the existing interface, with download progress,
  retry on failure and a manual check under Options.
- Verify the download size and SHA-256 digest over HTTPS before stopping the
  proxy, updating and restarting. Support both per-user installations and portable
  copies while preserving saved settings and DPAPI tokens.
- Notify hidden or minimized clients through the tray. Dismissing a version
  suppresses its prompt for the current session.
- Test release selection, version ordering, integrity, portable replacement and
  installer handoff. Cover update confirmation, progress and errors in UI previews.

Install this release manually to enable future updates. The server protocol
remains ETL v1; no server upgrade is required.

## 0.3.0 (2026-10-06)

- Add a per-user Windows installer with Start menu and Desktop shortcuts, repair
  and uninstall. Saved settings and tokens survive updates and uninstall.
- Add a monochrome SVG logo, PNG exports and application icons from 16 to 256
  pixels. Use the symbol in the desktop header, executable and tray.
- Follow the Windows light or dark appearance in the installer.
- Add executable version metadata and handle Windows session-end messages so
  Restart Manager can close the desktop during an update.
- Build and test the installer on Windows CI, including profile preservation.

## 0.2.1 (2026-10-05)

- Use a backup only after a background check verifies its TLS certificate and
  ETL token. Skip unavailable backups and check again every 30 seconds.
- Remove a backup from use when a connection fails; require a successful check
  before trying it for application traffic again.
- Increase the default connection budget from one to five seconds so slow
  primary authentication does not cause unnecessary failover. Saved settings
  retain their configured timeout.
- Cover offline backups, recovery, certificate rejection and concurrent failures
  in both the Node and Windows clients.

The server protocol remains ETL v1. No server upgrade is required.

## 0.2.0 (2026-10-03)

- Replace the Windows interface with Dear ImGui and DirectX 11, with Inter embedded
  in the portable executable.
- Keep the window borderless and 360 pixels wide. Options expands inline, with
  animated height changes and no scrollbars. Errors also adjust the window height.
- Add HTTP CONNECT to the Node client and preserve payload sent with the request.
- Bound native connection attempts, local proxy negotiation and idle sessions.
  Add traffic counters and safer worker shutdown.
- Reject malformed UTF-8 and non-object tunnel control messages.
- Add `etl doctor` for DNS, TCP and verified TLS checks without credentials.
- Rewrite setup, architecture, protocol and Windows documentation in plain English.

The wire protocol remains ETL v1. Existing server installations can serve the new
clients. The Node CLI requires Node.js 24 or later; the Windows executable does
not require Node.js or separate runtime DLLs.
