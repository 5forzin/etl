import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import tls from 'node:tls';
import net from 'node:net';
import { AgentRegistry } from '../src/agents.js';
import { createTunnelServer } from '../src/tunnel.js';
import { connected, protect, read, readFrame, writeFrame } from '../src/io.js';

const executable = process.env.ETL_AGENT;
const native = process.platform === 'win32' && process.env.ETL_NATIVE_CLIENT;
const execute = promisify(execFile);
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function freePort() {
  const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}

async function until(condition, timeout = 7000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { if (await condition()) return; await pause(50); }
  throw new Error('Agent did not reach the expected state');
}

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  const exit = once(child, 'exit'); child.kill(); await exit;
}

test('exported agent pairs once, preserves its identity, speaks ETL and stops after revocation',
  { skip: !executable, timeout: 60000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'etl-agent-bundle-'));
  const certPath = join(directory, 'controller.pem'), keyPath = join(directory, 'controller.key');
  const master = 'f'.repeat(64), tokenPath = join(directory, 'controller-token');
  const openssl = process.env.ETL_OPENSSL ?? (existsSync('C:/Program Files/Git/usr/bin/openssl.exe') ?
    'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl');
  let controller, agentProcess, duplicate, client;
  try {
    execFileSync(openssl, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '2', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
    writeFileSync(tokenPath, master);
    const ca = readFileSync(certPath, 'utf8');
    let probes = 0;
    const registry = new AgentRegistry({ path: join(directory, 'registry.json'), probe: async agent => {
      const socket = protect(tls.connect({ host: '127.0.0.1', port: agent.port, servername: agent.servername,
        ca: agent.ca, minVersion: 'TLSv1.3' }), 2000);
      try {
        await connected(socket, 'secureConnect');
        writeFrame(socket, { v: 1, token: agent.proxyToken });
        assert.deepEqual(await readFrame(socket), { code: 'OK' }); probes++;
      } finally { socket.destroy(); }
    } });
    controller = createTunnelServer({ key: readFileSync(keyPath), cert: ca, getToken: () => master, agents: registry });
    controller.listen(0, '127.0.0.1'); await once(controller, 'listening');
    const controllerPort = controller.address().port, port = await freePort();
    let grant;
    const settingsPath = join(directory, 'settings.json'), requestPath = join(directory, 'request.json');
    const responsePath = join(directory, 'response.json');
    if (native) {
      writeFileSync(settingsPath, JSON.stringify({ host: 'localhost', port: controllerPort, caFile: certPath, tokenFile: tokenPath }));
      writeFileSync(requestPath, JSON.stringify({ action: 'create', name: 'Integration server', port }));
      await execute(native, ['--self-test-agent-control', settingsPath, requestPath, responsePath], { windowsHide: true });
      grant = JSON.parse(readFileSync(responsePath));
    } else grant = registry.issue('Integration server', port);
    const metadata = { version: 1, id: grant.id, name: 'Integration server', pairingCode: grant.pairingCode, port,
      controller: { host: '127.0.0.1', port: controllerPort, servername: 'localhost', ca } };
    const bundle = join(directory, process.platform === 'win32' ? 'etl-agent.exe' : 'etl-agent');
    const metadataPath = join(directory, 'metadata.json');
    const exportedInput = native ? { ...metadata, controller: { ...metadata.controller,
      ca: ca.replace(/\r?\n/g, '\r\n') + readFileSync(keyPath, 'utf8') } } : metadata;
    writeFileSync(metadataPath, JSON.stringify(exportedInput));
    if (native) {
      await execute(native, ['--self-test-agent-export', 'windows', metadataPath, bundle], { windowsHide: true });
      const linuxPath = join(directory, 'etl-agent-linux');
      await execute(native, ['--self-test-agent-export', 'linux', metadataPath, linuxPath], { windowsHide: true });
      assert.deepEqual(readFileSync(linuxPath).subarray(0, 4), Buffer.from([127, 69, 76, 70]));
    } else {
      const payload = Buffer.from(JSON.stringify(metadata)), length = Buffer.alloc(4); length.writeUInt32BE(payload.length);
      writeFileSync(bundle, Buffer.concat([readFileSync(executable), payload, length, Buffer.from('ETLAGENT1')]), { mode: 0o700 });
    }
    const binary = readFileSync(bundle);
    assert.equal(binary.subarray(-9).toString(), 'ETLAGENT1');
    const footerSize = binary.readUInt32BE(binary.length - 13);
    const expected = structuredClone(metadata);
    if (native) expected.controller.ca = ca.replace(/\r\n/g, '\n');
    assert.deepEqual(JSON.parse(binary.subarray(-13-footerSize, -13)), expected);
    assert.ok(!binary.includes(Buffer.from(master)), 'controller credential must never be embedded');
    assert.ok(!binary.includes(readFileSync(keyPath)), 'CA files must not export private keys');
    const launch = profile => {
      const child = spawn(bundle, ['--public-ip', '1.1.1.1'], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, APPDATA: join(directory, profile), XDG_CONFIG_HOME: join(directory, profile) } });
      child.stdout.resume(); child.stderr.resume(); return child;
    };
    agentProcess = launch('profile');
    await until(() => registry.list().length === 1);
    assert.equal(probes, 1);
    const [entry] = registry.list();
    assert.equal(entry.host, '1.1.1.1');
    assert.equal(entry.port, port);
    assert.equal(entry.online, true);
    assert.equal(registry.canEnroll(grant.id, grant.pairingCode), undefined);
    const socket = protect(tls.connect({ host: '127.0.0.1', port, servername: entry.servername, ca: entry.ca,
      minVersion: 'TLSv1.3' }), 2000);
    try {
      await connected(socket, 'secureConnect'); writeFrame(socket, { v: 1, token: entry.proxyToken });
      assert.deepEqual(await readFrame(socket), { code: 'OK' });
      writeFrame(socket, { host: '169.254.169.254', port: 80 });
      assert.deepEqual(await readFrame(socket), { code: 'FAILED' });
    } finally { socket.destroy(); }
    if (native) {
      writeFileSync(requestPath, JSON.stringify({ action: 'list' }));
      await execute(native, ['--self-test-agent-control', settingsPath, requestPath, responsePath], { windowsHide: true });
      const response = JSON.parse(readFileSync(responsePath));
      assert.equal(response.count, 1); assert.equal(response.agents[0].servername, entry.servername);
      const agentCA = join(directory, 'agent.pem'), agentToken = join(directory, 'agent-token');
      writeFileSync(agentCA, entry.ca); writeFileSync(agentToken, entry.proxyToken);
      const localPort = await freePort();
      client = spawn(native, ['--headless', '--server', '127.0.0.1', '--server-port', String(port), '--servername', entry.servername,
        '--token-file', agentToken, '--ca', agentCA, '--port', String(localPort)], { windowsHide: true, stdio: 'ignore' });
      let local;
      await until(async () => {
        try { local = protect(net.connect({ host: '127.0.0.1', port: localPort }), 2000); await connected(local); return true; }
        catch { local?.destroy(); return false; }
      });
      try {
        local.write(Buffer.from([5, 1, 0])); assert.deepEqual(await read(local, 2), Buffer.from([5, 0]));
        local.write(Buffer.from([5, 1, 0, 1, 169, 254, 169, 254, 0, 80]));
        assert.equal((await read(local, 10))[1], 1);
      } finally { local.destroy(); await stop(client); client = undefined; }
    }
    await stop(agentProcess); agentProcess = undefined;
    duplicate = launch('duplicate-profile');
    await until(() => duplicate.exitCode !== null);
    assert.equal(duplicate.exitCode, 1, 'a copied bundle must not claim an enrolled identity');
    const lastSeen = registry.list()[0].lastSeen;
    agentProcess = launch('profile');
    await until(() => registry.list()[0].lastSeen > lastSeen);
    assert.equal(registry.list()[0].proxyToken, entry.proxyToken);
    registry.remove(grant.id);
    await until(() => agentProcess.exitCode !== null, 25000);
    assert.equal(agentProcess.exitCode, 1);
  } finally {
    await stop(client); await stop(agentProcess); await stop(duplicate);
    if (controller) await controller.shutdown();
    rmSync(directory, { recursive: true, force: true });
  }
});
