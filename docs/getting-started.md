# Setup and operations

Use the [Windows client](../native/windows/README.md) for a portable desktop
application, or Node.js 24+ for the CLI. The Node client needs no npm dependencies.
Tests require OpenSSL; Git for Windows' bundled executable is detected by the
Node test suite.

## Server prerequisites

Use a public Linux server, a domain resolving directly to it, an available TCP
port and a matching TLS certificate. Ordinary HTTP CDN proxying does not carry
ETL's custom TLS protocol. The default port is 443; any configured port must be
open in the host and provider firewalls. Do not replace an existing website's
listener to make room for ETL.

~~~sh
git clone https://github.com/5forzin/etl.git
cd etl
node src/cli.js --help
~~~

## Existing server with Docker

Prepare `secrets/fullchain.pem`, `secrets/privkey.pem` and `secrets/token`.
The certificate files must be real files rather than symlinks outside the mount.
For a new secrets directory on Linux:

~~~sh
install -d -m 700 secrets
umask 077
node src/cli.js token > secrets/token
# Copy the certificate chain and key into secrets before continuing.
sudo chown -R 1000:1000 secrets
sudo chmod 700 secrets
sudo chmod 600 secrets/token secrets/privkey.pem secrets/fullchain.pem
docker compose up -d --build
docker compose logs --tail=20
~~~

Do not regenerate a deployed token by rerunning the example. The container reads
secrets as UID/GID 1000. Set `ETL_PORT=24443` in a private local `.env` to select
another public port; the container still listens on 8443.

## Fresh Ubuntu host

`deploy/bootstrap.sh DOMAIN FULL_COMMIT_SHA` targets a dedicated Ubuntu 24.04
host. Run it as root after DNS and inbound TCP 80/443 are ready. Review the script
first: it installs Docker, Git, Certbot and OpenSSL, enables services, clones the
requested revision to `/opt/etl`, creates a token and obtains a certificate. It
refuses an existing `/opt/etl`.

The script accepts Let's Encrypt's terms without registering an email address.
On hosts with less than 1 GB RAM and no active swap, it also creates a 1 GB swap
file and adds it to `/etc/fstab`. It is an initial installer, not an upgrade tool.
HTTP-01 renewal requires port 80 to remain reachable. Its deploy hook copies the
renewed files and restarts ETL, interrupting active streams.

## Direct Node server

~~~sh
node src/cli.js server --port 8443 --cert secrets/fullchain.pem --key secrets/privkey.pem --token-file secrets/token
~~~

The [systemd unit](../deploy/etl.service) instead expects `/usr/bin/node`, a
dedicated `etl` user/group, source at `/opt/etl` and readable secrets under
`/etc/etl`. Provision those paths before installing the unit. It grants the
capability needed to bind port 443.

## Verify and connect

Copy the server token to a private client file through a trusted administrative
channel. Keep it out of shell arguments, Git and screenshots. Before using it:

~~~sh
node src/cli.js doctor --server tunnel.example.com --server-port 24443
node src/cli.js client --server tunnel.example.com --server-port 24443 --token-file secrets/token
curl --proxy socks5h://127.0.0.1:1080 https://example.com
curl --proxy http://127.0.0.1:1080 https://example.com
~~~

Doctor checks DNS, TCP, TLS 1.3 and certificate identity without sending a token
or destination. Add `--json` for a versioned report. Exit 0 means those checks
passed, 2 means a network/TLS check failed, and 1 means invalid configuration.
It does not prove ETL authentication or destination access works. The diagnostic
workflow in GitHub Actions runs the same verified checks.

Use `curl.exe` on Windows. `socks5h` sends destination names through ETL. Enable
proxy-side DNS in browsers as well. Node's HTTP port accepts CONNECT for HTTPS;
the Windows client additionally supports plain HTTP proxy requests. In ZCode,
set its HTTP Proxy to `http://127.0.0.1:1080` and restart the application.

If certificate verification fails, fix the certificate or endpoint. For a private
CA, pass `--ca PATH`; in Node this replaces the normal trust store, while the
native client adds it to its Windows/OpenSSL roots. Never disable verification.

### Automatic backup host

~~~sh
node src/cli.js client --server tunnel.example.com --token-file secrets/token \
  --fallback-server backup.example.com --fallback-token-file secrets/backup-token \
  --connect-timeout-ms 1000
~~~

Each host gets one setup budget covering DNS through authentication. Failures in
those phases move the new connection to an available backup. The client checks
the backup at startup and every 30 seconds after a check completes. A successful
check requires TLS 1.3, a valid certificate and ETL authentication; an open TCP port
alone does not qualify. Until a check succeeds, the backup is skipped. If a backup
connection fails, it is skipped again until another check succeeds. Checks send
no destination or application data and do not delay primary connections.

`--fallback-check-interval-ms` changes the interval (100–60000 ms). Omit the backup token file
only if both servers share a credential. `--fallback-port` defaults to the
primary port in Node. On Windows both ports are explicit settings, defaulting to
443. Increase the timeout for slow networks.

After authentication, destination setup has its own deadline. Established streams
never migrate and payloads are never replayed. Every new connection tries the
primary first. Leaving the backup host empty disables failover.

### Azure token enrollment

For an Azure VM prepared by the bootstrap, PowerShell 7 and Azure CLI can retrieve
the token through encrypted Run Command output:

~~~powershell
./deploy/enroll-azure.ps1 -ResourceGroup your-rg -VMName your-vm -TokenPath ./secrets/token
~~~

Create the destination directory first. The script restricts local permissions
and refuses to overwrite an existing token. This helper is for Azure; other hosts
use their normal trusted administrative channel.

## Certificates and local tests

For an isolated local test, create a one-day certificate in an ignored directory:

~~~sh
mkdir secrets
openssl req -x509 -newkey rsa:2048 -nodes -keyout secrets/privkey.pem -out secrets/fullchain.pem -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost
~~~

Run the server on 8443 and the client with `--server localhost --server-port 8443
--ca secrets/fullchain.pem`. Private destinations remain blocked. Automated
tests inject a local resolver only within their fixtures.

Certificates are loaded at startup. After replacing the mounted certificate and
key, run `docker compose restart etl`. The supplied renewal hook targets the
bootstrap's certificate name and paths; adapt it for other deployments.

## Rotation, upgrades and rollback

To revoke new sessions, generate a new private token file and atomically replace
`secrets/token`. Update clients and restart them. Restart the server if existing
authenticated streams must end immediately.

For an upgrade, record the current revision and container image, fetch the desired
revision in a separate checkout, and review/test it before rebuilding. Preserve
the existing secrets and configuration privately. Keep the previous image until
the new service passes doctor and an authenticated proxy request. A deployment
copy without Git metadata must be backed up or tied to a known release first.

Rollback recreates the service from that recorded revision/image with the same
secrets. Container recreation interrupts active sessions. `docker compose down`
stops the service and removes its network; source, images, certificates and token
files remain. Remove them separately only after checking their use. A systemd
installation must be stopped and disabled separately.

Defaults are 128 concurrent connections, ten seconds for negotiation/setup and
120 seconds of relay inactivity. `--max-connections` changes the Node cap. See
the [architecture](architecture.md) for per-host setup budgets and trust boundaries.
