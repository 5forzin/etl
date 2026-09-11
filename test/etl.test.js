import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createClient, createTunnelServer, tokenFile } from '../src/tunnel.js';
import { isPublicAddress, resolveDestination } from '../src/policy.js';
import { connected, protect, read, readFrame, writeFrame, track } from '../src/io.js';

const token = 'a'.repeat(64);
let directory, key, cert;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'etl-test-'));
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

async function listen(server, t) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.shutdown());
  return server.address().port;
}

async function tunnel(t, options = {}) {
  const server = createTunnelServer({ key, cert, getToken: () => token, ...options });
  return listen(server, t);
}

async function secure(t, port, options = {}) {
  const socket = protect(tls.connect({ host: '127.0.0.1', port, servername: 'localhost',
    ca: cert, minVersion: 'TLSv1.3', ...options }), 2000);
  t.after(() => socket.destroy());
  await connected(socket, 'secureConnect');
  return socket;
}

async function socks(t, port, host, destinationPort, extra = Buffer.alloc(0), command = 1) {
  const socket = protect(net.connect({ host: '127.0.0.1', port, allowHalfOpen: true }), 3000);
  t.after(() => socket.destroy());
  await connected(socket);
  socket.write(Buffer.from([5, 1, 0]));
  assert.deepEqual(await read(socket, 2), Buffer.from([5, 0]));
  const domain = Buffer.from(host);
  const destination = Buffer.alloc(2);
  destination.writeUInt16BE(destinationPort);
  socket.write(Buffer.concat([Buffer.from([5, command, 0, 3, domain.length]), domain, destination, extra]));
  const response = await read(socket, 10);
  return { socket, code: response[1] };
}

test('public destination policy rejects local, metadata, mapped and special addresses', () => {
  for (const address of ['0.0.0.0', '10.1.2.3', '127.0.0.1', '100.100.100.200',
    '169.254.169.254', '172.16.0.1', '192.168.1.1', '198.18.0.1', '224.0.0.1',
    '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', 'fc00::1', 'fe80::1',
    '2001:db8::1', '2002:7f00:1::1', '64:ff9b::7f00:1']) {
    assert.equal(isPublicAddress(address), false, address);
  }
  assert.equal(isPublicAddress('1.1.1.1'), true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
});

test('resolver rejects mixed DNS answers and preserves validated numeric results', async () => {
  await assert.rejects(resolveDestination('example.com', 443, async () => [
    { address: '1.1.1.1', family: 4 }, { address: '127.0.0.1', family: 4 },
  ]), /blocked/);
  let calls = 0;
  const result = await resolveDestination('example.com', 443, async () => {
    calls++; return [{ address: '1.1.1.1', family: 4 }];
  });
  assert.equal(calls, 1);
  assert.equal(result[0].address, '1.1.1.1');
  await assert.rejects(resolveDestination('example.com', 0));
});

test('invalid authentication never resolves a destination', async (t) => {
  let resolved = false;
  const port = await tunnel(t, { resolve: async () => { resolved = true; return []; } });
  const socket = await secure(t, port);
  writeFrame(socket, { v: 1, token: 'b'.repeat(64) });
  assert.deepEqual(await readFrame(socket), { code: 'AUTH' });
  assert.equal(resolved, false);
});

test('token file rotation revokes future authentication', async (t) => {
  const path = join(directory, 'token');
  writeFileSync(path, token);
  const port = await tunnel(t, { getToken: tokenFile(path) });
  const first = await secure(t, port);
  writeFrame(first, { v: 1, token });
  assert.equal((await readFrame(first)).code, 'OK');
  first.destroy();
  writeFileSync(path, 'b'.repeat(64));
  const second = await secure(t, port);
  writeFrame(second, { v: 1, token });
  assert.equal((await readFrame(second)).code, 'AUTH');
});

test('TLS rejects untrusted certificates and hostname mismatch', async (t) => {
  const port = await tunnel(t);
  await assert.rejects(secure(t, port, { ca: undefined }));
  await assert.rejects(secure(t, port, { servername: 'wrong.example' }));
});

test('oversized frames and private destinations fail closed', async (t) => {
  const port = await tunnel(t);
  const malformed = await secure(t, port);
  malformed.write(Buffer.from([255, 255]));
  assert.equal((await readFrame(malformed)).code, 'FAILED');
  const socket = await secure(t, port);
  writeFrame(socket, { v: 1, token });
  assert.equal((await readFrame(socket)).code, 'OK');
  writeFrame(socket, { host: '127.0.0.1', port: 80 });
  assert.equal((await readFrame(socket)).code, 'FAILED');
});

test('full SOCKS → TLS → destination relay preserves pipelined bytes and half-close', { timeout: 10000 }, async (t) => {
  const destination = track(net.createServer({ allowHalfOpen: true }, (socket) => {
    socket.on('error', () => {});
    socket.pipe(socket);
  }));
  const targetPort = await listen(destination, t);
  const domains = [];
  // Test-only injection: production always uses the public destination policy.
  const port = await tunnel(t, { resolve: async (host, requestedPort) => {
    domains.push(host);
    assert.equal(requestedPort, targetPort);
    return [{ address: '127.0.0.1', family: 4 }];
  } });
  const clientPort = await listen(createClient({ host: '127.0.0.1', servername: 'localhost',
    port, token, ca: cert }), t);
  await Promise.all(Array.from({ length: 4 }, async () => {
    const payload = randomBytes(96 * 1024);
    const { socket, code } = await socks(t, clientPort, 'remote-only.example', targetPort, payload);
    assert.equal(code, 0);
    socket.end();
    assert.deepEqual(await read(socket, payload.length), payload);
  }));
  assert.deepEqual(domains, Array(4).fill('remote-only.example'));
});

test('SOCKS rejects UDP ASSOCIATE and failed tunnel authentication', async (t) => {
  const port = await tunnel(t);
  const clientPort = await listen(createClient({ host: '127.0.0.1', servername: 'localhost',
    port, token: 'b'.repeat(64), ca: cert }), t);
  assert.equal((await socks(t, clientPort, 'example.com', 443, Buffer.alloc(0), 3)).code, 7);
  assert.equal((await socks(t, clientPort, 'example.com', 443)).code, 1);
});

test('absolute handshake deadline closes incomplete requests', async (t) => {
  const port = await tunnel(t, { handshakeTimeout: 200 });
  const socket = await secure(t, port);
  socket.resume();
  await once(socket, 'close');
  assert.equal(socket.destroyed, true);
});

test('fragmented control frames authenticate correctly', async (t) => {
  const port = await tunnel(t);
  const socket = await secure(t, port);
  const body = Buffer.from(JSON.stringify({ v: 1, token }));
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(body.length);
  for (const byte of Buffer.concat([prefix, body])) {
    socket.write(Buffer.from([byte]));
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal((await readFrame(socket)).code, 'OK');
});

test('client disconnect closes the active destination connection', { timeout: 3000 }, async (t) => {
  let destinationSocket;
  const destination = track(net.createServer((socket) => {
    destinationSocket = socket;
    socket.on('error', () => {});
    socket.resume();
  }));
  const targetPort = await listen(destination, t);
  const port = await tunnel(t, { resolve: async () => [{ address: '127.0.0.1', family: 4 }] });
  const clientPort = await listen(createClient({ host: '127.0.0.1', servername: 'localhost',
    port, token, ca: cert }), t);
  const { socket, code } = await socks(t, clientPort, 'remote.example', targetPort);
  assert.equal(code, 0);
  const closed = once(destinationSocket, 'close');
  socket.destroy();
  await closed;
});

test('connection limit rejects additional sockets', { timeout: 3000 }, async (t) => {
  const port = await tunnel(t, { maxConnections: 1 });
  await secure(t, port);
  await assert.rejects(secure(t, port));
});
