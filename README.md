# ETL

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/etl-logo-white.svg">
  <img src="assets/brand/etl-logo-black.svg" alt="ETL" width="150">
</picture>

ETL forwards TCP traffic through a server you control. A local SOCKS5 or HTTP
proxy opens a TLS 1.3 connection, authenticates with a token, and asks the server
to connect to the destination. Destination DNS runs on that server.

The Node.js client and server use built-in modules. The Windows client is a
portable C++ executable with Dear ImGui, DirectX 11 and Inter. It supports SOCKS5,
HTTP CONNECT, ordinary HTTP proxy requests, and a backup server. Windows stores
tokens with DPAPI for the current user.

The primary server is always tried first. A backup receives traffic only after a
background check verifies its TLS certificate and ETL token. Unavailable backups
are skipped and checked again every 30 seconds.

## Connect

Windows: download `ETL-Setup-VERSION-x64.exe` from
[releases](https://github.com/5forzin/etl/releases) and run it. The installer adds
ETL to the Start menu, offers a Desktop shortcut and installs for the current
user. Updates and uninstall preserve saved tokens and settings.

For a portable copy, download `etl-client.exe` instead. Both builds include the
same client. See the [Windows guide](native/windows/README.md) to build either.
Enter your server and token, set the remote port under Options, then click the power button.

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
