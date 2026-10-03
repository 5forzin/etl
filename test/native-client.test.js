import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { lookup } from 'node:dns/promises';
import { once } from 'node:events';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTunnelServer } from '../src/tunnel.js';
import { track, protect, read, readFrame, connected } from '../src/io.js';

const executable = process.env.ETL_NATIVE_CLIENT;

test('native Windows client fails over after a second with independent credentials and an absolute auth budget',
  { skip: !executable || process.platform !== 'win32', timeout: 15000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'etl-native-failover-'));
  const certPath = join(dir, 'cert.pem'), keyPath = join(dir, 'key.pem');
  const tokenPath = join(dir, 'token'), backupTokenPath = join(dir, 'backup-token');
  let backup, destination, blackhole, partial, child;
  try {
    execFileSync(process.env.ETL_OPENSSL ?? 'openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
    writeFileSync(tokenPath, 'a'.repeat(64));
    writeFileSync(backupTokenPath, 'b'.repeat(64));
    const key = readFileSync(keyPath), cert = readFileSync(certPath);
    destination = track(net.createServer((socket) => {
      socket.on('error', () => {}); socket.pipe(socket);
    }));
    const destinationPort = await listen(destination);
    backup = createTunnelServer({ key, cert, getToken: () => 'b'.repeat(64),
      resolve: async () => [{ address: '127.0.0.1', family: 4 }] });
    const backupPort = await listen(backup);
    blackhole = track(net.createServer((socket) => { socket.on('error', () => {}); socket.resume(); }));
    const blackholePort = await listen(blackhole);
    partial = track(tls.createServer({ key, cert, minVersion: 'TLSv1.3' }, (socket) => {
      socket.on('error', () => {});
      void readFrame(socket).then(() => {
        socket.write(Buffer.from([0, 100]));
        const drip = setInterval(() => socket.write(Buffer.from(' ')), 25);
        socket.once('close', () => clearInterval(drip));
      }).catch(() => {});
    }));
    const partialPort = await listen(partial);
    // Exercise the production one-second budget for both stalled phases. A
    // 200 ms backup handshake also measured Windows runner scheduling delays.
    for (const [primaryPort, timeout] of [[blackholePort, 1000], [partialPort, 1000]]) {
      const localPort = await freePort();
      const args = ['--headless', '--server', 'localhost', '--server-port', String(primaryPort),
        '--fallback-server', 'localhost', '--fallback-port', String(backupPort),
        '--fallback-token-file', backupTokenPath, '--port', String(localPort),
        '--token-file', tokenPath, '--ca', certPath];
      if (timeout !== 1000) args.push('--connect-timeout-ms', String(timeout));
      child = spawn(executable, args, { stdio: 'ignore', windowsHide: true });
      await awaitClient(localPort, child);
      const socket = protect(net.connect({ host: '127.0.0.1', port: localPort }), 5000);
      await connected(socket);
      socket.write(Buffer.from([5, 1, 0]));
      assert.deepEqual(await read(socket, 2), Buffer.from([5, 0]));
      const host = Buffer.from('remote.example');
      const payload = Buffer.from('native-backup-queued-payload');
      const started = performance.now();
      socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), host,
        Buffer.from([destinationPort >> 8, destinationPort & 255]), payload]));
      const phase = primaryPort === blackholePort ? 'TLS' : 'authentication';
      assert.equal((await readStage(socket, 10, `${phase} backup connect`))[1], 0, `backup failed with ${timeout} ms budget`);
      const elapsed = performance.now() - started;
      assert.ok(elapsed >= timeout * 0.7 && elapsed < timeout + 2000, `setup took ${elapsed} ms`);
      assert.deepEqual(await read(socket, payload.length), payload);
      await new Promise((resolve) => setTimeout(resolve, timeout + 100));
      socket.write(payload);
      assert.deepEqual(await read(socket, payload.length), payload);
      socket.destroy();
      const stopped = once(child, 'exit'); child.kill(); await stopped; child = undefined;
    }
  } finally {
    child?.kill();
    if (blackhole) await blackhole.shutdown();
    if (partial) await partial.shutdown();
    if (backup) await backup.shutdown();
    if (destination) await destination.shutdown();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('native Windows client protects stored tokens with DPAPI',
  { skip: !executable || process.platform !== 'win32' }, () => {
    execFileSync(executable, ['--self-test-token-storage'], { windowsHide: true });
  });

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

    const authority = `remote-only.example:${destinationPort}`;
    const http = protect(net.connect({ host: '127.0.0.1', port: localPort }), 5000);
    await connected(http);
    http.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    const connectedReply = Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n');
    assert.deepEqual(await readStage(http, connectedReply.length, 'HTTP CONNECT'), connectedReply);
    const httpPayload = Buffer.from('native-http-connect-to-etl');
    http.write(httpPayload);
    assert.deepEqual(await readStage(http, httpPayload.length, 'HTTP tunnel'), httpPayload);
    http.destroy();

    const plain = protect(net.connect({ host: '127.0.0.1', port: localPort }), 5000);
    await connected(plain);
    plain.write(`GET http://${authority}/probe HTTP/1.1\r\nHost: remote-only.example\r\nProxy-Connection: keep-alive\r\n\r\n`);
    const forwarded = Buffer.from('GET /probe HTTP/1.1\r\nHost: remote-only.example\r\nConnection: close\r\n\r\n');
    assert.deepEqual(await readStage(plain, forwarded.length, 'HTTP forward'), forwarded);
    plain.destroy();

    const malformed = protect(net.connect({ host: '127.0.0.1', port: localPort }), 5000);
    await connected(malformed);
    malformed.write('CONNECT remote-only.example HTTP/1.1\r\n\r\n');
    const badRequest = Buffer.from('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    assert.deepEqual(await readStage(malformed, badRequest.length, 'HTTP validation'), badRequest);
    malformed.destroy();

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

test('native client expires incomplete negotiations and idle relays',
  { skip: !executable || process.platform !== 'win32', timeout: 7000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'etl-native-deadlines-'));
  let server, destination, child;
  try {
    const certPath = join(dir, 'cert.pem'), keyPath = join(dir, 'key.pem'), tokenPath = join(dir, 'token');
    execFileSync(process.env.ETL_OPENSSL ?? 'openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
    writeFileSync(tokenPath, 'a'.repeat(64));
    destination = track(net.createServer(socket => { socket.on('error', () => {}); socket.pipe(socket); }));
    const targetPort = await listen(destination);
    server = createTunnelServer({ key: readFileSync(keyPath), cert: readFileSync(certPath), getToken: () => 'a'.repeat(64),
      resolve: async () => [{ address: '127.0.0.1', family: 4 }] });
    const remotePort = await listen(server), localPort = await freePort();
    child = spawn(executable, ['--headless', '--server', 'localhost', '--server-port', String(remotePort),
      '--token-file', tokenPath, '--ca', certPath, '--port', String(localPort),
      '--handshake-timeout-ms', '500', '--idle-timeout-ms', '300'], { stdio: 'ignore', windowsHide: true });
    await awaitClient(localPort, child);
    const incomplete = net.connect({ host: '127.0.0.1', port: localPort });
    await connected(incomplete); incomplete.on('error', () => {}); incomplete.resume();
    const closed = once(incomplete, 'close');
    const started = performance.now(); incomplete.write('CONNECT ');
    const drip = setInterval(() => incomplete.write('x'), 100);
    try { await closed; } finally { clearInterval(drip); incomplete.destroy(); }
    assert.ok(performance.now() - started >= 350, 'header closed before its deadline');
    const socket = protect(net.connect({ host: '127.0.0.1', port: localPort }), 2000);
    await connected(socket); socket.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(await read(socket, 2), Buffer.from([5, 0]));
    const host = Buffer.from('remote.example');
    socket.write(Buffer.concat([Buffer.from([5,1,0,3,host.length]),host,Buffer.from([targetPort >> 8, targetPort & 255])]));
    assert.equal((await read(socket, 10))[1], 0);
    socket.write('idle-test'); assert.equal((await read(socket, 9)).toString(), 'idle-test');
    const idleClose = once(socket, 'close'); socket.resume(); await idleClose;
    assert.equal(socket.destroyed, true);
  } finally {
    child?.kill(); if (server) await server.shutdown(); if (destination) await destination.shutdown();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('native client rejects a trailing headless option',
  { skip: !executable || process.platform !== 'win32' }, () => {
  assert.throws(() => execFileSync(executable, ['--headless', '--server'], { windowsHide: true }), e => e.status === 22);
});

test('native desktop renders a DirectX frame without reading user settings or starting a proxy',
  { skip: !executable || process.platform !== 'win32', timeout: 10000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'etl-ui-'));
  try {
    const path = join(dir, 'preview.bmp');
    execFileSync(executable, ['--self-test-ui', path], { windowsHide: true, timeout: 8000 });
    const bitmap = readFileSync(path);
    assert.equal(bitmap.subarray(0, 2).toString(), 'BM');
    assert.ok(bitmap.readInt32LE(18) >= 500);
    assert.ok(bitmap.length > 1_000_000);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
