# ETL

ETL forwards TCP traffic through a server you control. A local SOCKS5 or HTTP
proxy opens a TLS 1.3 connection, authenticates with a token, and asks the server
to connect to the destination. Destination DNS runs on that server.

The Node.js client and server use built-in modules. The Windows client is a
portable C++ executable with Dear ImGui, DirectX 11 and Inter. It supports SOCKS5,
HTTP CONNECT, ordinary HTTP proxy requests, and a backup server. Windows stores
tokens with DPAPI for the current user.

## Connect

Windows: build the client using the [Windows guide](native/windows/README.md),
or check [releases](https://github.com/5forzin/etl/releases) for published builds.
Enter your server and token, set the remote port under Options, then connect.
The new ImGui build is available only after it has been built or released from
this revision; older downloads may still use the previous interface.

With Node.js 24 or later:

~~~sh
node src/cli.js doctor --server tunnel.example.com
node src/cli.js client --server tunnel.example.com --token-file secrets/token
curl --proxy socks5h://127.0.0.1:1080 https://example.com
~~~

Use `curl.exe` on Windows. Both clients bind to `127.0.0.1`. Node accepts
HTTP CONNECT on the same port; the native client also handles plain HTTP URLs.
For a non-default server port, add `--server-port 24443`.

See [setup and operations](docs/getting-started.md) for certificates, Docker,
token provisioning and backup configuration.

## Scope

ETL currently forwards TCP. It has no UDP relay, TUN adapter or system-wide
routing. Applications must use the proxy. SOCKS clients should send hostnames
through it (`socks5h`); local DNS, UDP and WebRTC stay outside its coverage.

TLS protects the client-to-server link. The network can still see the endpoint
and traffic patterns. The exit host can see destination metadata. ETL has not
had an independent security audit and makes no anonymity or detectability claim.

## Develop

~~~sh
npm run check
npm test
~~~

Tests create temporary certificates with OpenSSL and use local listeners. Set
`ETL_NATIVE_CLIENT` to a built Windows EXE to include native integration and
DirectX rendering checks. Otherwise those tests are skipped.

- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Windows design and Figma sketch](docs/desktop-design.md)
- [Next work](docs/roadmap.md)
- [Security](SECURITY.md)

Keep tokens, private keys and client settings out of Git.
