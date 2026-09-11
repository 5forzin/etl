# ETL — Encrypted Transport Lab

A self-hosted encrypted tunnel for people with a domain and a server.

ETL aims to make deploying your own tunnel straightforward: configure a domain, run the server, and connect through a local client. The project explores transport design and traffic detectability through reproducible experiments.

**Status: experimental TCP MVP.** Client and server are implemented. Automated certificate provisioning, UDP, TUN, and traffic camouflage are not implemented.

Start with the [installation and client guide](docs/getting-started.md).

## Project goals

- Simple deployment on a Linux server with a public IP and a domain.
- A client and server developed as part of this project, without depending on WireGuard.
- Established TLS implementations for encryption and certificate validation.
- Authenticated access and destination DNS resolution on the server.
- Documented behavior, limitations, and repeatable network tests.

## Current implementation

The MVP exposes a SOCKS5 proxy on the client machine and forwards TCP connections through an authenticated TLS 1.3 connection to the ETL server. Applications must use proxy-side DNS to keep destination lookups on the server. It uses Node.js 24+ and only built-in modules.

```text
Browser → Local ETL SOCKS5 proxy → TLS tunnel → ETL server → Destination
```

The server will need inbound TCP port 443, outbound connectivity, and a valid certificate for its domain. Certificate provisioning and renewal are part of the deployment design. Sharing port 443 with an existing website requires a supported configuration and is not assumed in the initial MVP.

UDP forwarding and device-wide routing through a TUN interface are later milestones. The initial release will not route every application automatically.

## Security and detectability

ETL does not promise undetectability or anonymity. A network can observe the tunnel endpoint, connection metadata, and traffic patterns, and may block the connection. The server operator and hosting provider remain part of the trust model. TLS transport alone does not make a custom protocol look like ordinary web browsing.

See [architecture](docs/architecture.md), [wire protocol](docs/protocol.md), [roadmap](docs/roadmap.md), and [security policy](SECURITY.md).

## Development

```sh
node src/cli.js --help
npm run check
npm test
```

Tests generate temporary certificates with OpenSSL and exercise local SOCKS/TLS relaying, authentication, certificate verification, and destination policy. Docker Compose and a systemd unit are provided for deployment; see the guide for certificate and permission prerequisites.

Never commit credentials, private keys, client profiles, or production configuration.
