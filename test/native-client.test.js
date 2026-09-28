import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { once } from 'node:events';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTunnelServer } from '../src/tunnel.js';
import { track, protect, read, connected } from '../src/io.js';

const executable = process.env.ETL_NATIVE_CLIENT;

async function listen(server, host = '127.0.0.1') {
  server.listen(0, host);
  await once(server, 'listening');
  return server.address().port;
}

async function freePort() {
  const server = net.createServer();
  const port = await listen(server);
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function awaitClient(port, child) {
  for (let attempt = 0; attempt < 60; attempt++) {
    if (child.exitCode !== null) throw new Error(`Native client exited with ${child.exitCode}`);
    try {
      const socket = protect(net.connect({ host: '127.0.0.1', port }), 1000);
      await connected(socket);
      socket.destroy();
      return;
    } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error('Native client did not start');
}

async function readStage(socket, count, stage) {
  try { return await read(socket, count); }
  catch (error) { throw new Error(`${stage}: ${error.message}`, { cause: error }); }
}

test('native Windows client relays SOCKS5 through verified TLS to Node server',
  { skip: !executable || process.platform !== 'win32', timeout: 15000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'etl-native-'));
  const openssl = process.env.ETL_OPENSSL ?? 'openssl';
  const certPath = join(dir, 'cert.pem');
  const keyPath = join(dir, 'key.pem');
  const tokenPath = join(dir, 'token');
  let server, destination, child, mismatched;
  try {
    execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
    const token = 'a'.repeat(64);
    writeFileSync(tokenPath, token);
    destination = track(net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.on('error', () => {});
      socket.pipe(socket);
    }));
    const destinationPort = await listen(destination);
    server = createTunnelServer({ key: readFileSync(keyPath), cert: readFileSync(certPath),
      getToken: () => token, resolve: async () => [{ address: '127.0.0.1', family: 4 }] });
    const serverPort = await listen(server);
    const localPort = await freePort();
    child = spawn(executable, ['--headless', '--server', 'localhost', '--server-port', String(serverPort),
      '--port', String(localPort), '--token-file', tokenPath, '--ca', certPath],
    { stdio: 'ignore', windowsHide: true });
    await awaitClient(localPort, child);

    const socket = protect(net.connect({ host: '127.0.0.1', port: localPort, allowHalfOpen: true }), 5000);
    await connected(socket);
    socket.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(await readStage(socket, 2, 'SOCKS greeting'), Buffer.from([5, 0]));
    const hostname = Buffer.from('remote-only.example');
    socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, hostname.length]), hostname,
      Buffer.from([destinationPort >> 8, destinationPort & 255])]));
    assert.equal((await readStage(socket, 10, 'SOCKS connect'))[1], 0);
    const payload = Buffer.from('native-cpp-to-node-etl');
    socket.end(payload);
    assert.deepEqual(await readStage(socket, payload.length, 'relay'), payload);
    socket.destroy();

    const mismatchPort = await freePort();
    mismatched = spawn(executable, ['--headless', '--server', '127.0.0.1',
      '--server-port', String(serverPort), '--port', String(mismatchPort),
      '--token-file', tokenPath, '--ca', certPath],
    { stdio: 'ignore', windowsHide: true });
    await awaitClient(mismatchPort, mismatched);
    const rejected = protect(net.connect({ host: '127.0.0.1', port: mismatchPort }), 5000);
    await connected(rejected);
    rejected.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(await readStage(rejected, 2, 'mismatch greeting'), Buffer.from([5, 0]));
    rejected.write(Buffer.concat([Buffer.from([5, 1, 0, 3, hostname.length]), hostname,
      Buffer.from([destinationPort >> 8, destinationPort & 255])]));
    assert.equal((await readStage(rejected, 10, 'mismatch rejection'))[1], 1);
    rejected.destroy();
  } finally {
    mismatched?.kill();
    child?.kill();
    if (server) await server.shutdown();
    if (destination) await destination.shutdown();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('native Windows client reaches an IPv6-only ETL server through localhost',
  { skip: !executable || process.platform !== 'win32', timeout: 15000 }, async (t) => {
  if (!(await lookup('localhost', { all: true })).some((address) => address.family === 6)) {
    t.skip('localhost has no IPv6 address');
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'etl-native-ipv6-'));
  const openssl = process.env.ETL_OPENSSL ?? 'openssl';
  const certPath = join(dir, 'cert.pem');
  const keyPath = join(dir, 'key.pem');
  const tokenPath = join(dir, 'token');
  let server, destination, child;
  try {
    execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
    const token = 'a'.repeat(64);
    writeFileSync(tokenPath, token);
    destination = track(net.createServer((socket) => {
      socket.on('error', () => {});
      socket.pipe(socket);
    }));
    const destinationPort = await listen(destination);
    server = createTunnelServer({ key: readFileSync(keyPath), cert: readFileSync(certPath),
      getToken: () => token, resolve: async () => [{ address: '127.0.0.1', family: 4 }] });
    const serverPort = await listen(server, '::1');
    const localPort = await freePort();
    child = spawn(executable, ['--headless', '--server', 'localhost', '--server-port', String(serverPort),
      '--port', String(localPort), '--token-file', tokenPath, '--ca', certPath],
    { stdio: 'ignore', windowsHide: true });
    await awaitClient(localPort, child);

    const socket = protect(net.connect({ host: '127.0.0.1', port: localPort }), 5000);
    await connected(socket);
    socket.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(await readStage(socket, 2, 'IPv6 greeting'), Buffer.from([5, 0]));
    const hostname = Buffer.from('remote-only.example');
    socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, hostname.length]), hostname,
      Buffer.from([destinationPort >> 8, destinationPort & 255])]));
    assert.equal((await readStage(socket, 10, 'IPv6 SOCKS connect'))[1], 0);
    const payload = Buffer.from('native-ipv6-fallback');
    socket.write(payload);
    assert.deepEqual(await readStage(socket, payload.length, 'IPv6 relay'), payload);
    socket.destroy();
  } finally {
    child?.kill();
    if (server) await server.shutdown();
    if (destination) await destination.shutdown();
    rmSync(dir, { recursive: true, force: true });
  }
});
