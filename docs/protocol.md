# ETL wire protocol v1

This experimental protocol runs inside a verified TLS 1.3 connection. It does not implement HTTP or imitate a browser. One TLS connection carries one TCP destination. No multiplexing, UDP, TLS early data, or automatic reconnect is provided.

Control frames contain a two-byte unsigned big-endian length followed by UTF-8 JSON. Payload lengths must be between 2 and 1024 bytes. A connection must finish authentication, destination selection, DNS resolution and dialing within 10 seconds; incomplete handshakes close even if bytes continue arriving.

1. Client sends `{"v":1,"token":"<64 lowercase hex characters>"}`.
2. Server compares the token using constant-time comparison of SHA-256 digests and replies `{"code":"OK"}` or `{"code":"AUTH"}`. Failed authentication closes the connection without resolving a destination.
3. Client sends `{"host":"example.com","port":443}`.
4. Server validates the destination, resolves it, checks every returned address, and dials a validated numeric address. It replies `{"code":"OK"}` on success or `{"code":"FAILED"}` on failure.
5. Following success, all subsequent bytes are unframed TCP payload. Both sides preserve backpressure and half-close semantics. Errors and idle timeouts close the relay.

Malformed frames receive a generic failure when possible and the connection closes. Error responses deliberately exclude credentials and destination details.

The client implements SOCKS5 without local authentication, bound strictly to `127.0.0.1` by the CLI. CONNECT supports IPv4, IPv6, and domain addresses. BIND and UDP ASSOCIATE return command-not-supported. The local socket is accessible to other processes and users on that machine; it is not a boundary against an untrusted local user.

The server reads its single token file for every authentication. Replacing the file invalidates the old token for new connections. Restarting the server also terminates established sessions. The MVP has a global connection limit, not individual accounts or per-user quotas.
