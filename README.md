# ETL — Encrypted Transport Lab

A self-hosted encrypted tunnel for people with a domain and a server.

ETL aims to make deploying your own tunnel straightforward: configure a domain, run the server, and connect through a local client. The project explores transport design and traffic detectability through reproducible experiments.

**Status: project foundation. The client, server, and installer are not implemented yet.**

## Project goals

- Simple deployment on a Linux server with a public IP and a domain.
- A client and server developed as part of this project, without depending on WireGuard.
- Established TLS implementations for encryption and certificate validation.
- Authenticated access and destination DNS resolution on the server.
- Documented behavior, limitations, and repeatable network tests.

## Planned first release

The first MVP will expose a SOCKS5 proxy on the client machine and forward TCP connections through an authenticated TLS connection to the ETL server. Applications must use proxy-side DNS to keep destination lookups on the server.

```text
Browser → Local ETL SOCKS5 proxy → TLS tunnel → ETL server → Destination
```

The server will need inbound TCP port 443, outbound connectivity, and a valid certificate for its domain. Certificate provisioning and renewal are part of the deployment design. Sharing port 443 with an existing website requires a supported configuration and is not assumed in the initial MVP.

UDP forwarding and device-wide routing through a TUN interface are later milestones. The initial release will not route every application automatically.

## Security and detectability

ETL does not promise undetectability or anonymity. A network can observe the tunnel endpoint, connection metadata, and traffic patterns, and may block the connection. The server operator and hosting provider remain part of the trust model. TLS transport alone does not make a custom protocol look like ordinary web browsing.

See [architecture](docs/architecture.md), [roadmap](docs/roadmap.md), and [security policy](SECURITY.md).

## Development

This repository currently contains design documentation. Build commands and installation instructions will be added alongside working, tested implementations.

Never commit credentials, private keys, client profiles, or production configuration.
