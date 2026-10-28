import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import { once } from 'node:events';
import { AgentRegistry } from '../src/agents.js';
import { createTunnelServer } from '../src/tunnel.js';
import { connected, protect, readFrame, writeFrame } from '../src/io.js';

function fixture(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'etl-agents-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'agents.json');
  return { directory, path, registry: new AgentRegistry({ path, probe: async () => {}, ...options }) };
}

function certificate(directory, host) {
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  const openssl = process.env.ETL_OPENSSL ?? (existsSync(bundled) ? bundled : 'openssl');
  const keyPath = join(directory, `${host}.key`), certPath = join(directory, `${host}.pem`);
  execFileSync(openssl, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '2', '-subj', `/CN=${host}`,
    '-addext', `subjectAltName=DNS:${host}`, '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'pipe' });
  return { key: readFileSync(keyPath), cert: readFileSync(certPath, 'utf8') };
}

function identity(directory, grant) {
  return { host: '1.1.1.1', ca: certificate(directory, grant.servername).cert,
    proxyToken: 'b'.repeat(64), deviceToken: 'c'.repeat(64) };
}

test('agent grants expire, are hashed at rest and are bounded', t => {
  let time = Date.now();
  const { registry, path } = fixture(t, { now: () => time });
  const grant = registry.issue('Exit server', 443);
  assert.ok(registry.canEnroll(grant.id, grant.pairingCode));
  assert.ok(!readFileSync(path, 'utf8').includes(grant.pairingCode));
  assert.equal(registry.canEnroll(grant.id, 'd'.repeat(64)), undefined);
  assert.deepEqual(registry.list(), []);
  time = grant.expires;
  assert.equal(registry.canEnroll(grant.id, grant.pairingCode), undefined);
  for (let i = 0; i < 128; i++) registry.issue(`Server ${i}`, 443);
  assert.throws(() => registry.issue('Too many', 443), /limit/);
  assert.throws(() => registry.issue('Invalid', 0), /Invalid/);
});

test('agent enrollment is single use and restores from disk', async t => {
  const { registry, directory, path } = fixture(t);
  const grant = registry.issue('Primary exit', 443);
  const payload = identity(directory, grant);
  await registry.enroll(grant.id, grant.pairingCode, payload);
  await assert.rejects(registry.enroll(grant.id, grant.pairingCode, payload));
  const restored = new AgentRegistry({ path });
  const [agent] = restored.list();
  assert.equal(agent.name, 'Primary exit');
  assert.equal(agent.host, payload.host);
  assert.equal(agent.proxyToken, payload.proxyToken);
  assert.equal(agent.deviceHash, undefined);
  assert.equal(agent.online, true);
  assert.ok(restored.authorizedAgent(grant.id, payload.deviceToken));
  assert.equal(restored.authorizedAgent(grant.id, payload.proxyToken), undefined);
});

test('agent enrollment verifies its public listener before consuming the grant', async t => {
  let reachable = false, probes = 0;
  const { registry, directory } = fixture(t, { probe: async () => {
    probes++; if (!reachable) throw new Error('Unreachable');
  } });
  const grant = registry.issue('Exit', 8443), payload = identity(directory, grant);
  await assert.rejects(registry.enroll(grant.id, grant.pairingCode, { ...payload, host: '127.0.0.1' }));
  await assert.rejects(registry.enroll(grant.id, grant.pairingCode, { ...payload, ca: certificate(directory, 'wrong.example').cert }));
  assert.equal(probes, 0);
  await assert.rejects(registry.enroll(grant.id, grant.pairingCode, payload), /Unreachable/);
  assert.ok(registry.canEnroll(grant.id, grant.pairingCode));
  reachable = true;
  await registry.enroll(grant.id, grant.pairingCode, payload);
  assert.equal(registry.list().length, 1);
});

test('revoking a grant during its connectivity check prevents enrollment', async t => {
  let finishProbe;
  const { registry, directory } = fixture(t, { probe: () => new Promise(resolve => { finishProbe = resolve; }) });
  const grant = registry.issue('Exit', 443), payload = identity(directory, grant);
  const enrollment = registry.enroll(grant.id, grant.pairingCode, payload);
  await assert.rejects(registry.enroll(grant.id, grant.pairingCode, payload));
  registry.remove(grant.id);
  finishProbe();
  await assert.rejects(enrollment);
  assert.deepEqual(registry.list(), []);
});

test('agent heartbeats authenticate, expire online status and honor revocation', async t => {
  let time = Date.now(), probes = 0;
  const { registry, directory } = fixture(t, { now: () => time, probe: async () => { probes++; } });
  const grant = registry.issue('Exit', 443), payload = identity(directory, grant);
  await registry.enroll(grant.id, grant.pairingCode, payload);
  time += 61000;
  assert.equal(registry.list()[0].online, false);
  await assert.rejects(registry.heartbeat(grant.id, payload.proxyToken, '8.8.8.8'));
  await assert.rejects(registry.heartbeat(grant.id, payload.deviceToken, '169.254.169.254'));
  await registry.heartbeat(grant.id, payload.deviceToken, '8.8.8.8');
  assert.equal(probes, 2);
  assert.equal(registry.list()[0].online, true);
  assert.equal(registry.list()[0].host, '8.8.8.8');
  registry.remove(grant.id);
  await assert.rejects(registry.heartbeat(grant.id, payload.deviceToken, '8.8.8.8'));
});

test('registry management requires the controller credential over verified TLS', async t => {
  const { registry, directory } = fixture(t);
  const { key, cert } = certificate(directory, 'localhost');
  const token = 'a'.repeat(64);
  const server = createTunnelServer({ key, cert, getToken: () => token, agents: registry });
  t.after(() => server.shutdown());
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const connect = async credential => {
    const socket = protect(tls.connect({ host: '127.0.0.1', port: server.address().port,
      servername: 'localhost', ca: cert, minVersion: 'TLSv1.3' }), 2000);
    t.after(() => socket.destroy());
    await connected(socket, 'secureConnect');
    writeFrame(socket, { v: 3, mode: 'manage', token: credential });
    return socket;
  };
  const denied = await connect('d'.repeat(64));
  assert.deepEqual(await readFrame(denied), { code: 'AUTH' });
  const allowed = await connect(token);
  assert.deepEqual(await readFrame(allowed), { code: 'OK' });
  writeFrame(allowed, { action: 'create', name: 'New server', port: 443 });
  const grant = await readFrame(allowed);
  assert.equal(grant.code, 'OK');
  assert.equal(grant.port, 443);
  assert.match(grant.id, /^[a-f0-9]{32}$/);
});
