# Roadmap

## 0. Foundation

- [x] Define project identity and intended audience.
- [x] Document the proposed architecture and trust boundaries.
- [ ] Select implementation language and TLS library.
- [ ] Specify version 1 framing, authentication, configuration, and error codes.

## 1. Functional TCP MVP

- [ ] Implement the server with TLS and mandatory authentication.
- [ ] Implement a loopback SOCKS5 client with CONNECT support.
- [ ] Resolve destination domains on the server.
- [ ] Implement credential revocation, destination restrictions, and resource limits.
- [ ] Test relaying, invalid input, cancellation, authentication, DNS, and certificates.

## 2. Easy self-hosting

- [ ] Package reproducible releases with checksums.
- [ ] Provide a Linux service and a documented installation workflow.
- [ ] Automate certificate provisioning and renewal using a defined deployment model.
- [ ] Provide client configuration generation without exposing secrets.
- [ ] Document upgrade, rollback, and uninstall procedures.
- [ ] Validate deployment on a clean server using only the public guide.

## 3. Network experiments

- [ ] Publish a reproducible lab and baseline captures with sensitive data removed.
- [ ] Measure throughput, latency, resource use, and failure behavior.
- [ ] Evaluate traffic classification and active-probing behavior.
- [ ] Document observed detectability and supported network conditions.

## 4. Expanded transport

- [ ] Evaluate UDP forwarding and QUIC as an additional transport.
- [ ] Add TUN integration and explicit IPv4, IPv6, and DNS routing behavior.
- [ ] Design and test device-wide failure handling and leak protection.

These milestones describe planned work and do not imply release dates or existing capabilities.
