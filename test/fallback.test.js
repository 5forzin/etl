import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createClient, createTunnelServer } from '../src/tunnel.js';
import { track, protect, connected, read, readFrame, writeFrame } from '../src/io.js';

const token = 'a'.repeat(64), backupToken = 'b'.repeat(64);
let directory, key, cert, keyPath, certPath, tokenPath, backupTokenPath;
before(() => {
  directory = mkdtempSync(join(tmpdir(), 'etl-backup-health-'));
  keyPath = join(directory, 'key.pem'); certPath = join(directory, 'cert.pem');
  tokenPath = join(directory, 'token'); backupTokenPath = join(directory, 'backup-token');
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  execFileSync(process.env.ETL_OPENSSL ?? (existsSync(bundled) ? bundled : 'openssl'),
    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
      '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio:'pipe' });
  key = readFileSync(keyPath); cert = readFileSync(certPath);
  writeFileSync(tokenPath, token); writeFileSync(backupTokenPath, backupToken);
});
after(() => { if (directory) rmSync(directory, { recursive:true, force:true }); });

async function listen(server, t) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.shutdown()); return server.address().port;
}

async function waitFor(predicate) {
  const deadline = performance.now() + 4000;
  while (!predicate()) {
    if (performance.now() > deadline) throw new Error('Backup health check did not finish');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

function backupFixture() {
  const state = { authenticated:false, connections:0, replies:0, closed:0, destinations:0 };
  const server = track(tls.createServer({key, cert, minVersion:'TLSv1.3'}, socket => {
    state.connections++; socket.on('error', () => {});
    socket.once('close', () => { state.closed++; });
    void (async () => {
      const hello = await readFrame(socket);
      assert.equal(hello.token, backupToken);
      state.replies++;
      writeFrame(socket, {code:state.authenticated ? 'OK' : 'AUTH'});
      if (!state.authenticated) { socket.end(); return; }
      await readFrame(socket);
      state.destinations++;
      writeFrame(socket, {code:'OK'});
      socket.pipe(socket);
    })().catch(() => socket.destroy());
  }));
  return {server, state};
}

async function startClient(kind, t, primaryPort, backupPort, interval = 10000, backupHost = 'localhost') {
  if (kind === 'Node') {
    return listen(createClient({host:'127.0.0.1', port:primaryPort, servername:'localhost', token, ca:cert,
      connectTimeout:300, fallbackCheckInterval:interval,
      fallbacks:[{host:'127.0.0.1', port:backupPort,
        servername:backupHost === '127.0.0.1' ? 'wrong.example' : backupHost, token:backupToken}]}), t);
  }
  const reservation = net.createServer();
  reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const child = spawn(process.env.ETL_NATIVE_CLIENT,
    ['--headless','--server','localhost','--server-port',String(primaryPort),'--port',String(port),
      '--token-file',tokenPath,'--ca',certPath,'--fallback-server',backupHost,
      '--fallback-port',String(backupPort),'--fallback-token-file',backupTokenPath,
      '--connect-timeout-ms','300','--fallback-check-interval-ms',String(interval)],
    {stdio:'ignore', windowsHide:true});
  t.after(async () => {
    if (child.exitCode !== null) return;
    const exited = once(child, 'exit'); child.kill(); await exited;
  });
  for (let attempt = 0; attempt < 80; attempt++) {
    if (child.exitCode !== null) throw new Error(`Native client exited: ${child.exitCode}`);
    try {
      const socket = net.connect({host:'127.0.0.1',port}); socket.on('error', () => {});
      await connected(socket); socket.destroy(); return port;
    } catch { await new Promise(resolve => setTimeout(resolve, 25)); }
  }
  throw new Error('Native client did not start');
}

async function request(port, expected) {
  const socket = protect(net.connect({host:'127.0.0.1',port}), 3000);
  try {
    await connected(socket); socket.write(Buffer.from([5,1,0]));
    assert.deepEqual(await read(socket,2), Buffer.from([5,0]));
    const host = Buffer.from('remote.example');
    socket.write(Buffer.concat([Buffer.from([5,1,0,3,host.length]),host,Buffer.from([1,187])]));
    assert.equal((await read(socket,10))[1], expected);
    if (expected === 0) {
      socket.write('backup-payload');
      assert.equal((await read(socket,14)).toString(), 'backup-payload');
    }
  } finally { socket.destroy(); }
}

for (const kind of ['Node', 'native Windows']) {
  const options = {skip:kind !== 'Node' && (!process.env.ETL_NATIVE_CLIENT || process.platform !== 'win32'), timeout:10000};
  test(`${kind} skips an offline backup during concurrent primary failures`, options, async t => {
    const primary = createTunnelServer({key,cert,getToken:() => backupToken});
    const primaryPort = await listen(primary,t);
    let attempts = 0;
    const backup = track(net.createServer(socket => { attempts++; socket.on('error', () => {}); socket.resume(); }));
    const backupPort = await listen(backup,t);
    const port = await startClient(kind,t,primaryPort,backupPort);
    await waitFor(() => attempts === 1);
    await Promise.all(Array.from({length:12}, () => request(port,1)));
    assert.equal(attempts,1,'requests retried an unavailable backup');
  });

  test(`${kind} keeps primary traffic working while its backup check stalls`, options, async t => {
    const echo = track(tls.createServer({key,cert,minVersion:'TLSv1.3'}, socket => {
      socket.on('error', () => {});
      void (async () => {
        assert.equal((await readFrame(socket)).token,token);
        writeFrame(socket,{code:'OK'}); await readFrame(socket);
        writeFrame(socket,{code:'OK'}); socket.pipe(socket);
      })().catch(() => socket.destroy());
    }));
    const primaryPort = await listen(echo,t);
    const backup = track(net.createServer(socket => { socket.on('error', () => {}); socket.resume(); }));
    const backupPort = await listen(backup,t);
    const checking = once(backup,'connection');
    const port = await startClient(kind,t,primaryPort,backupPort);
    await checking;
    await request(port,0);
  });

  test(`${kind} restores a backup only after ETL authentication succeeds`, options, async t => {
    const primaryPort = await listen(createTunnelServer({key,cert,getToken:() => backupToken}),t);
    const {server,state} = backupFixture();
    const backupPort = await listen(server,t);
    const port = await startClient(kind,t,primaryPort,backupPort,200);
    await waitFor(() => state.closed > 0);
    await request(port,1);
    assert.equal(state.destinations,0,'an authentication failure received application traffic');
    state.authenticated = true;
    const previous = state.closed;
    await waitFor(() => state.closed > previous);
    await request(port,0);
    assert.equal(state.destinations,1,'a probe opened a destination');
  });

  test(`${kind} removes a previously healthy backup after its first connection failure`, options, async t => {
    const primaryPort = await listen(createTunnelServer({key,cert,getToken:() => backupToken}),t);
    const {server,state} = backupFixture(); state.authenticated = true;
    const backupPort = await listen(server,t);
    const port = await startClient(kind,t,primaryPort,backupPort);
    await waitFor(() => state.closed > 0);
    await request(port,0);
    state.authenticated = false;
    await request(port,1);
    const attempts = state.connections;
    await Promise.all(Array.from({length:8}, () => request(port,1)));
    assert.equal(state.connections,attempts,'a failed backup remained eligible');
  });

  test(`${kind} rejects backup certificate mismatch before sending credentials`, options, async t => {
    const primaryPort = await listen(createTunnelServer({key,cert,getToken:() => backupToken}),t);
    const {server,state} = backupFixture(); state.authenticated = true;
    const backupPort = await listen(server,t);
    server.on('tlsClientError', () => {});
    const port = await startClient(kind,t,primaryPort,backupPort,10000,'127.0.0.1');
    await request(port,1);
    assert.equal(state.replies,0);
    assert.equal(state.destinations,0);
  });
}

test('Node shutdown cancels a pending backup check without waiting for its timeout', {timeout:3000}, async t => {
  const backup = track(net.createServer(socket => { socket.on('error', () => {}); socket.resume(); }));
  const backupPort = await listen(backup,t);
  const client = createClient({host:'localhost', token, connectTimeout:60000,
    fallbacks:[{host:'127.0.0.1', port:backupPort}]});
  const checking = once(backup,'connection');
  await listen(client,t); await checking;
  const started = performance.now();
  await Promise.all([client.shutdown(),client.shutdown()]);
  assert.ok(performance.now()-started < 1000);
});

test('backup check intervals are bounded', () => {
  for (const fallbackCheckInterval of [0,99,60001,NaN,Infinity]) {
    assert.throws(() => createClient({host:'localhost',token,fallbackCheckInterval}));
  }
});
