#!/usr/bin/env bash
# Run as root on a fresh Ubuntu 24.04 host after DNS points to its public IP.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -euo pipefail

domain=${1:?Usage: bootstrap.sh DOMAIN COMMIT}
revision=${2:?Supply the reviewed Git commit to deploy}
[[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || { echo 'Invalid domain' >&2; exit 1; }
[[ "$revision" =~ ^[a-f0-9]{40}$ ]] || { echo 'Expected full commit SHA' >&2; exit 1; }
[[ $(id -u) == 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ ! -e /opt/etl ]] || { echo '/opt/etl already exists; refusing to overwrite it' >&2; exit 1; }

# Small lab VMs need headroom while apt and Docker unpack packages.
if [[ $(awk '/MemTotal/ {print $2}' /proc/meminfo) -lt 1000000 ]] && ! swapon --show --noheadings | grep -q .; then
  [[ ! -e /swapfile-etl ]] || { echo '/swapfile-etl already exists' >&2; exit 1; }
  fallocate -l 1G /swapfile-etl
  chmod 600 /swapfile-etl
  mkswap /swapfile-etl
  swapon /swapfile-etl
  printf '/swapfile-etl none swap sw 0 0\n' >> /etc/fstab
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io docker-compose-v2 certbot git openssl
systemctl enable --now docker
git clone https://github.com/5forzin/etl.git /opt/etl
git -C /opt/etl checkout --detach "$revision"
install -d -m 700 -o 1000 -g 1000 /opt/etl/secrets
umask 077
openssl rand -hex 32 > /opt/etl/secrets/token
chown 1000:1000 /opt/etl/secrets/token

# HTTP-01 needs inbound TCP 80. ETL serves its separate TLS protocol on 443.
certbot certonly --standalone --non-interactive --agree-tos \
  --register-unsafely-without-email --cert-name etl -d "$domain"
install -m 600 -o 1000 -g 1000 /etc/letsencrypt/live/etl/fullchain.pem /opt/etl/secrets/fullchain.pem
install -m 600 -o 1000 -g 1000 /etc/letsencrypt/live/etl/privkey.pem /opt/etl/secrets/privkey.pem
install -m 700 /opt/etl/deploy/renew-certificate.sh /etc/letsencrypt/renewal-hooks/deploy/etl
systemctl enable --now certbot.timer
cd /opt/etl
docker compose up -d --build
docker compose ps
