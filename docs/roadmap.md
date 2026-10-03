# Next work

The current revision forwards TCP through verified TLS, supports SOCKS5 and HTTP
CONNECT, and can fail over before opening a destination. Windows also forwards
ordinary HTTP requests and has a portable ImGui/DirectX 11 client. Setup,
certificate renewal, token rotation and rollback are documented.

## Priorities

1. **Separate credentials and quotas.** Replace the shared server token with
   revocable client identities; test that one client cannot exhaust another's
   capacity. Keep v1 compatibility explicit during the migration.
2. **Measure load.** Record throughput, setup latency, memory and shutdown time
   under concurrent sessions, slow readers, stalled DNS and destination failures.
3. **Exercise deployment.** Run the public bootstrap, renewal and rollback on a
   clean Ubuntu host. The existing live host is not evidence that a clean install
   works from the current revision.
4. **Improve desktop integration.** Validate high-DPI layouts, GPU reset recovery,
   keyboard operation and accessibility. ImGui's screen reader support remains
   limited.

## Transport experiments

Evaluate QUIC only after measuring whether setup cost or TCP loss is the limiting
factor. A UDP relay needs its own destination policy, resource limits and tests.
TUN requires explicit IPv4, IPv6, DNS and failure routing before it can claim
device-wide coverage. None of these features has shipped.

Detectability experiments must include the network environment, baseline,
capture method and observed limits. Passing one filter is not a general guarantee.
