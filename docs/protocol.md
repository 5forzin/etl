# ETL protocol v1

ETL v1 carries one TCP destination inside a verified TLS 1.3 connection. The
transport is custom TLS, not HTTPS. There is no early data, multiplexing or UDP.

## Frames

A control frame contains a two-byte unsigned big-endian length followed by
2–1024 bytes of UTF-8 JSON. The Node parser rejects invalid UTF-8, JSON arrays,
null and scalar values. The native client accepts the server's canonical
`{"code":"OK"}` response.

| Step | Sender | Payload or action |
| --- | --- | --- |
| 1 | Client | `{"v":1,"token":"<64 lowercase hex characters>"}` |
| 2 | Server | `{"code":"OK"}` or `{"code":"AUTH"}` |
| 3 | Client | `{"host":"example.com","port":443}` |
| 4 | Server | Validate, resolve, check every address, then dial a numeric address |
| 5 | Server | `{"code":"OK"}` or `{"code":"FAILED"}` |
| 6 | Both | Relay unframed application bytes |

The server gives the entire setup ten seconds, including DNS and dialing. Failed
authentication closes the connection without resolving a destination. Malformed
requests receive FAILED when possible. Replies exclude tokens and destination
details. Successful relays preserve half-close behavior.

## Local protocols

SOCKS5 uses no local authentication and supports CONNECT with IPv4, IPv6 or a
hostname. BIND returns command-not-supported. UDP ASSOCIATE opens a v2 TLS
session authenticated with `v: 2`, `mode: "udp"` and the proxy token. Datagrams
contain a framed `{host, port}` header followed by a 16-bit payload length and
at most 1500 payload bytes. A `{code: "FAILED"}` control frame has no payload
and drops one rejected destination. SOCKS5 clients must select proxy-side DNS
if they want the server to resolve destinations.

HTTP CONNECT uses an authority such as `example.com:443` or
`[2606:4700:4700::1111]:443`. On success the local proxy returns
`HTTP/1.1 200 Connection Established`, then relays bytes already queued after
the header. Node rejects oversized headers, invalid authorities, transfer encoding
and nonzero content lengths; malformed or failed requests receive 502. It does
not forward ordinary GET requests. The native client additionally supports
absolute-form HTTP and responds with 400 to malformed requests.

## Failover and credentials

Before destination setup, clients may try a backup after a primary connection,
TLS or authentication failure. Every host keeps certificate verification enabled
and may have an independent token. Payloads are never replayed and streams never
migrate. New connections always try the primary first.

Each server rereads its shared token file at authentication. Replacing it revokes
new sessions; restarting terminates existing ones. There are no per-user quotas.

## Agent control (v3)

Control requests use the same verified TLS 1.3 connection and 16-bit frame length.
The first frame is limited to 1024 bytes. After authentication, frames may contain
up to 16384 bytes. The complete exchange shares the server's handshake deadline.

| Mode | Initial frame fields | Request actions |
| --- | --- | --- |
| `manage` | `v: 3`, `mode`, controller `token` | `create`, `list`, `remove` |
| `enroll` | `v: 3`, `mode`, agent `id`, pairing `code` | `enroll` |
| `agent` | `v: 3`, `mode`, agent `id`, device `token` | `heartbeat` |

The server replies `{"code":"OK"}` before accepting an action, or `AUTH` and
closes. `create` takes a name and port and returns `id`, `pairingCode`, `port`,
`expires` and `servername`. The one-use code expires after 24 hours. `list`
returns an OK frame with `count`, followed by that many agent records. These
records include the proxy credential and public CA and require controller authentication.
`remove` takes an `id` and revokes both pending and registered identities.

`enroll` supplies a public numeric `host`, separate `proxyToken` and `deviceToken`
values, and a self-signed CA certificate for `ID.etl-agent`. The controller probes
the pinned TLS listener on the grant's port before consuming the grant. A heartbeat
supplies the current public host; changed addresses are probed again. Actions reply
OK or FAILED. Invalid actions reply INVALID. All control connections then close.

Agent proxy traffic continues to use v1 TCP and v2 UDP, with the agent's proxy
token and certificate. The device token cannot authenticate proxy traffic.
