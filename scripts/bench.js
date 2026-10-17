// Baseline benchmark for the full client path: local SOCKS5 -> TLS 1.3 ->
// tunnel server -> destination. Measures what a system-wide VPN mode would
// stress: single-flow throughput, full-setup flow rate and memory.
//
// Usage: node scripts/bench.js [--mib 256] [--flows 200] [--lanes 16] [--save]
// --save appends one JSON line per run to scripts/bench-results.json.
import { execFileSync } from 'node:child_process';
import { existsSync, appendFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { read, connected } from '../src/io.js';
import { createClient, createTunnelServer } from '../src/tunnel.js';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(`--${name}`);
  return index === -1 ? fallback : Number(args[index + 1]);
};
const mebibytes = option('mib', 256);
const flows = option('flows', 200);
const lanes = option('lanes', 16);
if (!Number.isInteger(mebibytes) || mebibytes < 1 || !Number.isInteger(flows) ||
    flows < 1 || !Number.isInteger(lanes) || lanes < 1 || lanes > 128) {
  console.error('Usage: node scripts/bench.js [--mib N] [--flows N] [--lanes N] [--save]');
  process.exit(22);
}

const openssl = process.env.ETL_OPENSSL ??
  (existsSync('C:/Program Files/Git/usr/bin/openssl.exe') ?
    'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl');
const directory = mkdtempSync(join(tmpdir(), 'etl-bench-'));
const prefix = join(directory, 'cert');
execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
  '-keyout', `${prefix}.key`, '-out', `${prefix}.crt`], { stdio: 'pipe' });

const token = randomBytes(32).toString('hex');
const key = readFileSync(`${prefix}.key`);
const cert = readFileSync(`${prefix}.crt`);
const echo = net.createServer((socket) => socket.pipe(socket));
const tunnel = createTunnelServer({ key, cert, getToken: () => token, maxConnections: 256,
  resolve: async () => [{ address: '127.0.0.1', family: 4 }] });
await new Promise((resolve) => echo.listen(0, '127.0.0.1', resolve));
await new Promise((resolve) => tunnel.listen(0, '127.0.0.1', resolve));
const client = createClient({ host: '127.0.0.1', port: tunnel.address().port,
  servername: 'localhost', token, ca: cert, maxConnections: 256 });
await new Promise((resolve) => client.listen(0, '127.0.0.1', resolve));
const echoPort = echo.address().port;
const socksPort = client.address().port;

async function negotiate(socket) {
  socket.write(Buffer.from([5, 1, 0]));
  if ((await read(socket, 2))[1] !== 0) throw new Error('No acceptable SOCKS method');
  socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1,
    echoPort >> 8, echoPort & 0xff]));
  const head = await read(socket, 4);
  if (head[1] !== 0) throw new Error(`SOCKS reply ${head[1]}`);
  await read(socket, head[3] === 1 ? 6 : head[3] === 4 ? 18 : 8);
}

async function openFlow() {
  const socket = net.connect({ host: '127.0.0.1', port: socksPort });
  await connected(socket);
  await negotiate(socket);
  return socket;
}

const results = { date: new Date().toISOString(), node: process.version,
  params: { mebibytes, flows, lanes } };

{
  const socket = await openFlow();
  const total = mebibytes * 1024 * 1024;
  const chunk = Buffer.alloc(64 * 1024, 7);
  let received = 0;
  const done = new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.on('data', (data) => { received += data.length; if (received >= total) resolve(); });
  });
  const start = performance.now();
  let sent = 0;
  while (sent < total) {
    sent += chunk.length;
    if (!socket.write(chunk)) await once(socket, 'drain');
  }
  await done;
  const seconds = (performance.now() - start) / 1000;
  socket.destroy();
  results.throughput = { mebibytes, seconds: +seconds.toFixed(3),
    mbps: +(mebibytes / seconds).toFixed(1) };
  console.log(`throughput  ${results.throughput.mbps} MiB/s ` +
    `(${mebibytes} MiB in ${seconds.toFixed(3)}s, echoed back)`);
}

{
  const start = performance.now();
  for (let i = 0; i < flows; i++) (await openFlow()).destroy();
  const seconds = (performance.now() - start) / 1000;
  results.flowsSequential = { flows, seconds: +seconds.toFixed(3),
    perSecond: +(flows / seconds).toFixed(1),
    meanMs: +(seconds * 1000 / flows).toFixed(2) };
  console.log(`flows seq   ${results.flowsSequential.perSecond}/s ` +
    `(${results.flowsSequential.meanMs} ms per full setup)`);
}

{
  const perLane = Math.ceil(flows / lanes);
  const start = performance.now();
  await Promise.all(Array.from({ length: lanes }, async () => {
    for (let i = 0; i < perLane; i++) (await openFlow()).destroy();
  }));
  const seconds = (performance.now() - start) / 1000;
  results.flowsParallel = { lanes, flows: perLane * lanes, seconds: +seconds.toFixed(3),
    perSecond: +(perLane * lanes / seconds).toFixed(1) };
  console.log(`flows par   ${results.flowsParallel.perSecond}/s ` +
    `(${lanes} lanes, ${perLane * lanes} flows in ${seconds.toFixed(3)}s)`);
}

results.memory = {
  rssMiB: +(process.memoryUsage().rss / 1048576).toFixed(1),
  heapMiB: +(process.memoryUsage().heapUsed / 1048576).toFixed(1),
};
console.log(`memory      rss ${results.memory.rssMiB} MiB, heap ${results.memory.heapMiB} MiB`);

if (args.includes('--save')) {
  appendFileSync(new URL('./bench-results.json', import.meta.url),
    JSON.stringify(results) + '\n');
  console.log('saved       scripts/bench-results.json');
}

await Promise.all([client.shutdown(), tunnel.shutdown(), echo.close()]);
rmSync(directory, { recursive: true, force: true });
