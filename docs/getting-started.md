# Getting started

ETL 0.1 is an experimental TCP proxy. It is not a device-wide VPN or an undetectable transport.

## Requirements

- Node.js 24 or newer on the client and server, or Docker Compose for the server.
- A public Linux server with outbound internet access and inbound TCP 443 available.
- A domain pointing directly to that server. Disable ordinary HTTP CDN proxying for this hostname: ETL speaks custom TLS, not HTTP.
- A valid TLS certificate and matching private key for the hostname. Use an ACME client or the fresh-server bootstrap below.

No npm dependencies are required. Clone the repository on each machine:

```sh
git clone https://github.com/5forzin/etl.git
cd etl
node src/cli.js --help
```

## Server with Docker Compose

### Fresh Ubuntu server bootstrap

On a dedicated, fresh Ubuntu 24.04 server, `deploy/bootstrap.sh DOMAIN FULL_COMMIT_SHA`
installs Docker and Certbot, clones the specified ETL revision to `/opt/etl`, generates
a private token, obtains a Let's Encrypt certificate and enables automated renewal.
Run it as root after the domain resolves directly to the server and inbound TCP 80
and 443 are permitted. It accepts the Let's Encrypt terms and registers without an
email address. On hosts with less than 1 GB RAM and no swap, it also adds a 1 GB
swap file at `/swapfile-etl` and an entry to `/etc/fstab`.

This script installs system packages and enables services; use it on a dedicated
host. It refuses to overwrite an existing `/opt/etl`. Review it before running.
TCP 80 must remain reachable for HTTP-01 renewals. The renewal hook copies the
new certificate into the container's secret directory and restarts ETL, briefly
interrupting active sessions. Retrieve `/opt/etl/secrets/token` through a trusted
administrative channel and save it privately on your client.

The bootstrap is an initial deployment workflow, not an idempotent upgrade tool.
For removal, stop the Compose service and handle the certificate, installed packages,
and optional swap entry separately after checking whether they are still in use.

### Existing certificate/manual setup

Create a private `secrets` directory containing `fullchain.pem`, `privkey.pem`, and `token`. Generate a token with:

```sh
node src/cli.js token
```

Save the generated value as a single line in `secrets/token` and transfer it to the client through a trusted channel. Treat it as a password. Do not put it in command-line arguments, Git, or screenshots.

The container runs as UID/GID 1000. On Linux, give that identity read access to the directory and files. For example, for a newly prepared ETL secrets directory:

```sh
sudo chown -R 1000:1000 secrets
sudo chmod 700 secrets
sudo chmod 600 secrets/token secrets/privkey.pem secrets/fullchain.pem
docker compose up -d --build
docker compose logs --tail=20
```

This binds host TCP 443. If another service owns that port, choose a different published port and use `--server-port` on the client. Do not replace an existing web service configuration without planning the change. Open the selected port in both the host firewall and the provider firewall.

The directory must contain actual certificate files, not symlinks pointing outside the mounted directory. Your certificate renewal process must securely update these files and run `docker compose restart etl` to load the renewed certificate. ETL does not watch certificate files automatically.

## Run directly with Node

For an unprivileged test, use port 8443:

```sh
node src/cli.js server --port 8443 --cert secrets/fullchain.pem --key secrets/privkey.pem --token-file secrets/token
```

The optional [systemd unit](../deploy/etl.service) expects Node at `/usr/bin/node`, the repository at `/opt/etl`, a dedicated `etl` user/group, and certificate/token files under `/etc/etl` readable by that user. Adapt and provision those paths before installing the unit. It grants only the capability needed to bind port 443; no installer changes your host automatically.

## Connect from your computer

Put the server's token in `secrets/token` locally, then run:

```sh
node src/cli.js client --server vpn.example.com --token-file secrets/token
```

For a server on a different port, add `--server-port 8443`.

Configure your browser's SOCKS5 proxy as `127.0.0.1:1080` and enable proxy-side DNS. For example, Firefox exposes a “Proxy DNS when using SOCKS v5” setting. A command-line check is:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

On Windows, use `curl.exe`. The `socks5h` scheme sends the destination hostname through the tunnel for server-side resolution. An application that resolves names locally can still leak DNS queries. Browser UDP/WebRTC and other applications are outside this TCP proxy's coverage.

## Local certificate testing

With OpenSSL available, create an ephemeral localhost certificate in an ignored directory:

```sh
mkdir secrets
openssl req -x509 -newkey rsa:2048 -nodes -keyout secrets/privkey.pem -out secrets/fullchain.pem -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost
```

Start the server on 8443 and connect with `--server localhost --server-port 8443 --ca secrets/fullchain.pem`. Certificate verification remains enabled. The server still rejects private destinations: use a public destination for manual testing. The automated suite uses an injected resolver solely within its local lab.

## Operations

- **Revoke access:** atomically replace `secrets/token` with a newly generated token. New connections must use the new value. Restart the server to terminate already authenticated sessions; restart clients after updating their token file.
- **Upgrade:** record the current Git commit, fetch and review the desired version, then rebuild with `docker compose up -d --build`. Back up configuration privately.
- **Rollback:** deploy the previously recorded commit in a separate checkout with the existing secrets and recreate the container. Active connections are interrupted.
- **Stop/uninstall:** `docker compose down` removes the Compose service and network. Source files, local image and secrets remain; remove those explicitly only when no longer needed. A manually installed systemd service must be stopped, disabled and removed separately.
- **Limits:** 128 simultaneous connections per process, a 10-second setup deadline, and a 120-second idle timeout. Use `--max-connections` when running directly to change the connection cap. There is one shared credential in this MVP.

Logs contain startup and listener errors, not per-destination browsing records. Container infrastructure and the hosting provider may have their own logs.

## Development checks

```sh
npm run check
npm test
```

Tests require OpenSSL to generate ephemeral TLS fixtures. On Windows, Git for Windows' bundled OpenSSL is detected automatically; otherwise put OpenSSL on PATH or set `ETL_OPENSSL` to its executable path. Tests use local listeners, never depend on a live internet destination, and remove their generated keys afterward.
