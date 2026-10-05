# Architecture

Each proxied TCP connection gets its own TLS connection. ETL does not multiplex
streams or replay application data after a failure.

~~~text
Application → loopback proxy → TLS 1.3 → ETL server → destination
~~~

## Client

The Node client accepts SOCKS5 CONNECT and HTTP CONNECT. The native Windows client
also rewrites absolute-form HTTP requests for the destination. Both use the same
[ETL v1 protocol](protocol.md), verify the server certificate and authenticate
before requesting a destination.

New connections try the primary host first, then an available backup. A background
check authenticates each backup over verified TLS before it becomes eligible.
Unknown or unavailable backups are skipped. Checks repeat 30 seconds after the
previous check finishes, without opening destinations or relaying payloads. A
failed backup connection removes it from use until a later check succeeds.
Availability can change between a check and a request, so every request still
verifies TLS and authenticates before sending a destination.

Each attempt
has one deadline covering DNS, TCP, TLS and authentication; the default is five
seconds. Once a host accepts authentication, destination setup gets a separate
deadline. A destination failure does not trigger failover. Existing streams stay
on their original server and close if it fails.

The Windows renderer lives in `native/windows/desktop_ui.cpp`; networking and
DPAPI storage remain in `etl_client.cpp`. DirectX 11 falls back to WARP when a
hardware device cannot be created. Hidden or minimized windows wait for messages
instead of rendering. The main screen shows listener state and byte counters,
not a remote health guarantee. The primary connects when an application uses
the proxy; a configured backup also receives the background checks.

## Server

The server accepts TLS 1.3, reads an authentication frame, and compares token
digests in constant time. It reads the token file on each authentication so an
atomic replacement revokes future sessions. Existing sessions require a restart
to terminate.

Only authenticated clients can request DNS or destination connections. The
destination policy rejects private, loopback, link-local, metadata, mapped IPv4
and special-use addresses. A DNS answer containing any blocked address rejects
the whole request. Connections use validated numeric addresses without resolving
the hostname again.

## Limits and failure handling

| Control | Default |
| --- | --- |
| Concurrent accepted connections | 128 per process |
| ETL control payload | 2–1024 bytes |
| Local HTTP header | 16 KiB |
| Local negotiation | 10 seconds |
| Server authentication through destination setup | 10 seconds total |
| Client attempt through authentication | 5 seconds per host |
| Client destination setup | 10 seconds |
| Backup check interval after completion | 30 seconds |
| Relay inactivity | 120 seconds |

Absolute deadlines expire even when a peer drips bytes. The native relay tracks
actual activity to enforce its idle limit. Shutdown interrupts listeners and
active sockets; Node shutdown is safe to request more than once. Node pipes
provide backpressure, while the native relay uses bounded 16 KiB buffers and
blocking writes with timeouts.

## Trust and deployment

Local processes can use the loopback proxy without authentication. The tunnel
has one shared token per server, not user accounts or per-user quotas. Windows
encrypts stored tokens with current-user DPAPI; a process running as that same
user can decrypt them. Node reads private token files.

Compose runs the server as an unprivileged user with a read-only filesystem,
dropped capabilities and memory/process limits. The systemd unit is an alternative
for direct Node deployment. Certificates are loaded at startup, so renewal restarts
the service and interrupts its streams. See [operations](getting-started.md).

QUIC, UDP, TUN, multiplexing and traffic camouflage are not implemented.
