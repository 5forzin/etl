#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient, createTunnelServer, tokenFile } from './tunnel.js';

const help = `ETL — Encrypted Transport Lab (experimental TCP MVP)

node src/cli.js token
node src/cli.js server --cert fullchain.pem --key privkey.pem --token-file secrets/token
node src/cli.js client --server vpn.example.com --token-file secrets/token

Options:
  --port NUMBER          Server/listener port (server: 443; client: 1080)
  --server-port NUMBER   Remote TLS port (client: 443)
  --listen IP            Server bind address (default: 0.0.0.0)
  --ca PATH              Additional trust anchor for a private/test CA
  --max-connections N    Maximum simultaneous connections (default: 128)

Client always binds to 127.0.0.1. Configure SOCKS5 with remote DNS.
Token files contain one 64-character lowercase hex token.
`;

function port(value, fallback) {
  const result = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(result) || result < 1 || result > 65535) throw new Error('Invalid port');
  return result;
}

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    help: { type: 'boolean', short: 'h' }, cert: { type: 'string' },
    key: { type: 'string' }, 'token-file': { type: 'string' },
    server: { type: 'string' }, port: { type: 'string' },
    'server-port': { type: 'string' }, listen: { type: 'string' },
    ca: { type: 'string' }, 'max-connections': { type: 'string' },
  } });
  const [command] = positionals;
  if (values.help || !command) { console.log(help); return; }
  if (positionals.length !== 1) throw new Error('Expected one command');
  if (command === 'token') { console.log(randomBytes(32).toString('hex')); return; }
  if (!['server', 'client'].includes(command)) throw new Error('Unknown command; use --help');
  if (!values['token-file']) throw new Error('--token-file is required');
  const getToken = tokenFile(values['token-file']);
  const maxConnections = Number(values['max-connections'] ?? 128);
  if (!Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > 10000) {
    throw new Error('--max-connections must be between 1 and 10000');
  }
  let service, bind, listenPort;
  if (command === 'server') {
    if (!values.cert || !values.key) throw new Error('--cert and --key are required');
    service = createTunnelServer({ cert: readFileSync(values.cert),
      key: readFileSync(values.key), getToken, maxConnections });
    bind = values.listen ?? '0.0.0.0';
    listenPort = port(values.port, 443);
  } else {
    if (!values.server) throw new Error('--server is required');
    if (values.listen) throw new Error('Client binds only to loopback; omit --listen');
    service = createClient({ host: values.server, port: port(values['server-port'], 443),
      token: getToken(), ca: values.ca ? readFileSync(values.ca) : undefined, maxConnections });
    bind = '127.0.0.1';
    listenPort = port(values.port, 1080);
  }
  service.on('error', (error) => {
    console.error(`ETL: listener failed (${error.code ?? 'unknown'}). Check address, port and permissions.`);
    process.exitCode = 1;
  });
  service.listen(listenPort, bind, () => console.log(`ETL ${command} listening on ${bind}:${listenPort}`));
  const stop = () => {
    void service.shutdown().catch(() => { process.exitCode = 1; });
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

main().catch((error) => { console.error(`ETL: ${error.message}`); process.exitCode = 1; });
