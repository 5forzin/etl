# Changelog

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
