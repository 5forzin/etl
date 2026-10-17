import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createClient, createTunnelServer } from '../src/tunnel.js';
import { connected, protect, read, readFrame, writeFrame } from '../src/io.js';
import { buildUdpPacket, parseUdpPacket, readDatagram, writeDatagram } from '../src/udp.js';

const token = 'a'.repeat(64);
let directory, key, cert;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'etl-udp-'));
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  const openssl = process.env.ETL_OPENSSL ?? (existsSync(bundled) ? bundled : 'openssl');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'),
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
  { stdio: 'pipe' });
  key = readFileSync(join(directory, 'key.pem'));
  cert = readFileSync(join(directory, 'cert.pem'));
});
after(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });

const local = async () => [{ address: '127.0.0.1', family: 4 }];

async function listen(server, t) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.shutdown());
  return server.address().port;
}

async function tunnel(t, options = {}) {
  const server = createTunnelServer({ key, cert, getToken: () => token,
    resolve: local, ...options });
  return listen(server, t);
}

async function secure(t, port, options = {}) {
  const socket = protect(tls.connect({ host: '127.0.0.1', port, servername: 'localhost',
    ca: cert, minVersion: 'TLSv1.3', ...options }), 3000);
  t.after(() => socket.destroy());
  await connected(socket, 'secureConnect');
  return socket;
}

async function udpSession(t, port, options = {}) {
  const socket = await secure(t, port, options);
  writeFrame(socket, { v: 2, token, mode: 'udp' });
  assert.equal((await readFrame(socket)).code, 'OK');
  return socket;
}

async function udpEcho(t) {
  const echo = dgram.createSocket('udp4');
  echo.on('message', (message, rinfo) => echo.send(message, rinfo.port, rinfo.address));
  echo.on('error', () => {});
  echo.bind(0, '127.0.0.1');
  await once(echo, 'listening');
  t.after(() => echo.close());
  return echo.address().port;
}

async function associate(t, port) {
  const socket = protect(net.connect({ host: '127.0.0.1', port }), 3000);
  t.after(() => socket.destroy());
  await connected(socket);
  socket.write(Buffer.from([5, 1, 0]));
  assert.deepEqual(await read(socket, 2), Buffer.from([5, 0]));
  socket.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
  const response = await read(socket, 10);
  assert.equal(response[1], 0);
  return { socket, relayPort: response.readUInt16BE(8) };
}

test('udp packet codec round-trips addresses and rejects fragments', () => {
  for (const [host, expected] of [['9.9.9.9', '9.9.9.9'],
    ['2606:4700:4700:0:0:0:0:1111', '2606:4700:4700:0:0:0:0:1111'],
    ['2606:4700:4700::1111', '2606:4700:4700:0:0:0:0:1111'],
    ['::1', '0:0:0:0:0:0:0:1'], ['example.com', 'example.com']]) {
    const parsed = parseUdpPacket(buildUdpPacket(host, 53, Buffer.from('query')));
    assert.equal(parsed.host, expected);
    assert.equal(parsed.port, 53);
    assert.deepEqual(parsed.payload, Buffer.from('query'));
  }
  assert.equal(parseUdpPacket(Buffer.from([0, 0, 1, 1, 8, 8, 8, 8, 0, 53])), null);
  assert.equal(parseUdpPacket(Buffer.from([0, 0, 0, 9])), null);
  assert.equal(parseUdpPacket(Buffer.alloc(3)), null);
});

test('v2 udp session relays datagrams and drops blocked destinations', { timeout: 5000 }, async (t) => {
  const echoPort = await udpEcho(t);
  const port = await tunnel(t, { resolve: async (host) => {
    if (host === 'blocked.example') throw new Error('Destination blocked');
    return local();
  } });
  const socket = await udpSession(t, port);
  writeDatagram(socket, 'echo.example', echoPort, Buffer.from('ping'));
  const reply = await readDatagram(socket, 1500);
  assert.equal(reply.host, '127.0.0.1');
  assert.equal(reply.port, echoPort);
  assert.deepEqual(reply.payload, Buffer.from('ping'));
  writeDatagram(socket, 'blocked.example', 53, Buffer.from('q'));
  assert.deepEqual(await readFrame(socket), { code: 'FAILED' });
  writeDatagram(socket, 'echo.example', echoPort, Buffer.from('pong'));
  assert.deepEqual((await readDatagram(socket, 1500)).payload, Buffer.from('pong'));
});

test('v2 udp session requires a valid token', async (t) => {
  const port = await tunnel(t);
  const socket = await secure(t, port);
  writeFrame(socket, { v: 2, token: 'b'.repeat(64), mode: 'udp' });
  assert.deepEqual(await readFrame(socket), { code: 'AUTH' });
});

test('v2 udp session rejects oversized datagrams', { timeout: 3000 }, async (t) => {
  const port = await tunnel(t, { maxDatagram: 64 });
  const socket = await udpSession(t, port);
  writeFrame(socket, { host: 'echo.example', port: 53 });
  const length = Buffer.alloc(2);
  length.writeUInt16BE(65);
  socket.write(Buffer.concat([length, Buffer.alloc(65)]));
  await once(socket, 'close');
  assert.equal(socket.destroyed, true);
});

test('destination cache evicts the least recently used entry', { timeout: 5000 }, async (t) => {
  const echoPort = await udpEcho(t);
  const resolved = [];
  const port = await tunnel(t, { maxDestinations: 1, resolve: async (host) => {
    resolved.push(host);
    return local();
  } });
  const socket = await udpSession(t, port);
  for (const host of ['one.example', 'two.example', 'one.example']) {
    writeDatagram(socket, host, echoPort, Buffer.from(host));
    assert.deepEqual((await readDatagram(socket, 1500)).payload, Buffer.from(host));
  }
  assert.deepEqual(resolved, ['one.example', 'two.example', 'one.example']);
});

test('SOCKS5 UDP ASSOCIATE relays datagrams through the tunnel', { timeout: 6000 }, async (t) => {
  const echoPort = await udpEcho(t);
  const port = await tunnel(t);
  const clientPort = await listen(createClient({ host: '127.0.0.1', servername: 'localhost',
    port, token, ca: cert }), t);
  const { socket, relayPort } = await associate(t, clientPort);
  const app = dgram.createSocket('udp4');
  app.on('error', () => {});
  app.bind(0, '127.0.0.1');
  await once(app, 'listening');
  t.after(() => app.close());
  const reply = once(app, 'message', { signal: AbortSignal.timeout(4000) });
  app.send(buildUdpPacket('echo.example', echoPort, Buffer.from('udp works')),
    relayPort, '127.0.0.1');
  const [message] = await reply;
  const parsed = parseUdpPacket(message);
  assert.equal(parsed.host, '127.0.0.1');
  assert.equal(parsed.port, echoPort);
  assert.deepEqual(parsed.payload, Buffer.from('udp works'));
  socket.destroy();
});

test('closing the association tears the v2 session down', { timeout: 4000 }, async (t) => {
  const server = createTunnelServer({ key, cert, getToken: () => token, resolve: local });
  const port = await listen(server, t);
  const clientPort = await listen(createClient({ host: '127.0.0.1', servername: 'localhost',
    port, token, ca: cert }), t);
  const { socket } = await associate(t, clientPort);
  await new Promise((resolve) => setTimeout(resolve, 100));
  socket.destroy();
  const settled = new Promise((resolve) => {
    const check = () => server.getConnections((error, count) => {
      if (error || count === 0) resolve();
      else setTimeout(check, 50);
    });
    check();
  });
  await Promise.race([settled, new Promise((_, reject) =>
    setTimeout(() => reject(new Error('session leaked')), 3000))]);
});
