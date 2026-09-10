# Architecture

Status: initial proposal. These are implementation requirements, not claims about existing software.

## Components

The client binds a SOCKS5 endpoint to loopback by default. For the first MVP it accepts CONNECT requests for TCP destinations; unsupported commands must fail explicitly. It forwards domain names to the server for resolution when the application supplies a domain instead of a resolved IP.

The server terminates TLS, authenticates the client, validates the requested destination against its access policy, and relays bytes. No destination connection or DNS lookup is made for an unauthenticated request.

The initial implementation should favor one authenticated tunnel connection per proxied TCP connection. Multiplexing can be evaluated after the basic relay, cancellation, resource limits, and error handling are validated.

## Transport

Use a maintained TLS library with hostname and certificate verification enabled. Do not implement cryptographic primitives or disable certificate checks. Define a versioned application protocol with bounded message lengths, explicit response codes, and handshake deadlines.

Credentials must be provisioned separately from public configuration, revocable, and excluded from logs. Do not enable replayable early data for authentication or destination-opening requests.

## Deployment experience

The intended user supplies a domain pointing to a public Linux server, installs ETL, provisions a certificate and credential, and imports a client configuration. The implementation must document prerequisites and provide an actionable error when a port is occupied or DNS is misconfigured.

The deployment workflow must cover certificate renewal, service restart, upgrades, rollback, and uninstall. Installers must explain changes to the host and avoid silently replacing firewall or web-server configuration.

## Trust boundaries and resource controls

- The local proxy listens on loopback unless explicitly configured otherwise.
- The remote server requires authentication and must never default to an open proxy.
- Block loopback, link-local, private, and infrastructure metadata destinations by default, including IPv6 equivalents. Evaluate resolved addresses and connect only to validated addresses to limit DNS rebinding risks.
- Bound concurrent sessions, handshake size, connection time, idle time, and per-client resource use.
- Operational logs should avoid destination histories, payloads, and credentials by default. Document any configurable logging and retention.
- A failed tunnel must close the proxied connection. Device-wide leak protection requires a separate TUN and routing design.

## Limitations

The access network sees the server IP and traffic patterns and may see the TLS hostname. It can block the server or recognize the transport. The exit server can see destination metadata and any application traffic that is not independently encrypted. A single self-hosted endpoint does not provide anonymity among a large population of users.

## Validation before release

Verify authentication rejection and revocation, malformed-frame handling, DNS behavior, destination restrictions, concurrent relay correctness, timeouts, and certificate validation. Exercise the documented installation on a clean server and connection from a separate client.

For detectability experiments, record the environment, baseline traffic, captures, detection method, and limitations. Treat passing a particular filter as an experimental result, not a general guarantee.
