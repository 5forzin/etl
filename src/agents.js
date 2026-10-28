import tls from 'node:tls';
import { createHash, randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { connected, protect, readFrame, writeFrame } from './io.js';
import { isPublicAddress } from './policy.js';

const FRAME_LIMIT = 16384;
const MAX_AGENTS = 128;
const CODE_LIFETIME = 24 * 60 * 60 * 1000;
const hash = value => createHash('sha256').update(value).digest('hex');
const secret = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const matches = (value, expected) => secret(value) && typeof expected === 'string' &&
  /^[a-f0-9]{64}$/.test(expected) && timingSafeEqual(Buffer.from(hash(value), 'hex'), Buffer.from(expected, 'hex'));

async function probeAgent({ host, port, servername, ca, proxyToken }) {
  const socket = protect(tls.connect({ host, port, servername, ca,
    rejectUnauthorized: true, minVersion: 'TLSv1.3' }), 3000);
  const deadline = setTimeout(() => socket.destroy(), 3000);
  try {
    await connected(socket, 'secureConnect');
    writeFrame(socket, { v: 1, token: proxyToken });
    if ((await readFrame(socket)).code !== 'OK') throw new Error('Agent authentication failed');
  } finally { clearTimeout(deadline); socket.destroy(); }
}

export class AgentRegistry {
  constructor({ path, now = Date.now, probe = probeAgent } = {}) {
    if (!path) throw new Error('Agent state path is required');
    this.path = path;
    this.now = now;
    this.probe = probe;
    this.claims = new Set();
    this.state = { version: 1, pending: [], agents: [] };
    try {
      const source = readFileSync(path, 'utf8');
      if (Buffer.byteLength(source) > 4 * 1024 * 1024) throw new Error('Agent state is too large');
      const state = JSON.parse(source);
      if (state.version !== 1 || !Array.isArray(state.pending) || !Array.isArray(state.agents) ||
          state.pending.length > MAX_AGENTS || state.agents.length > MAX_AGENTS) throw new Error('Invalid agent state');
      this.state = state;
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }

  save(next) {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${process.pid}.tmp`;
    writeFileSync(temporary, JSON.stringify(next), { mode: 0o600, flag: 'w' });
    renameSync(temporary, this.path);
    this.state = next;
  }

  issue(name, port) {
    if (typeof name !== 'string' || !name.trim() || name.length > 64 || /[\x00-\x1f]/.test(name) ||
        !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid agent settings');
    const pending = this.state.pending.filter(entry => entry.expires > this.now());
    if (pending.length + this.state.agents.length >= MAX_AGENTS) throw new Error('Agent limit reached');
    const id = randomBytes(16).toString('hex');
    const code = randomBytes(32).toString('hex');
    const expires = this.now() + CODE_LIFETIME;
    this.save({ ...this.state, pending: [...pending, { id, name: name.trim(), port, codeHash: hash(code), expires }] });
    return { id, pairingCode: code, port, expires, servername: `${id}.etl-agent` };
  }

  list() {
    return this.state.agents.map(({ deviceHash, ...agent }) => ({ ...agent,
      online: this.now() - agent.lastSeen < 60000 }));
  }

  remove(id) {
    if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw new Error('Invalid agent');
    this.save({ ...this.state, pending: this.state.pending.filter(entry => entry.id !== id),
      agents: this.state.agents.filter(entry => entry.id !== id) });
  }

  authorizedAgent(id, token) {
    return this.state.agents.find(entry => entry.id === id && matches(token, entry.deviceHash));
  }

  canEnroll(id, code) {
    return this.state.pending.find(entry => entry.id === id && entry.expires > this.now() && matches(code, entry.codeHash));
  }

  async enroll(id, code, payload) {
    const pending = this.canEnroll(id, code);
    if (!pending || this.claims.has(id)) throw new Error('Pairing code is unavailable');
    if (!isPublicAddress(payload?.host) || !secret(payload?.proxyToken) || !secret(payload?.deviceToken) ||
        typeof payload?.ca !== 'string' || payload.ca.length > 4096) throw new Error('Invalid agent identity');
    const servername = `${id}.etl-agent`;
    const certificate = new X509Certificate(payload.ca);
    if (!certificate.ca || certificate.checkHost(servername) !== servername ||
        !certificate.verify(certificate.publicKey) || Date.parse(certificate.validFrom) > this.now() ||
        Date.parse(certificate.validTo) < this.now() + CODE_LIFETIME) throw new Error('Invalid agent certificate');
    const agent = { id, name: pending.name, host: payload.host, port: pending.port, servername,
      ca: payload.ca, proxyToken: payload.proxyToken, deviceHash: hash(payload.deviceToken), lastSeen: this.now() };
    this.claims.add(id);
    try {
      await this.probe(agent);
      // A removal or expiry during the connectivity check must still revoke the grant.
      if (!this.canEnroll(id, code)) throw new Error('Pairing code is unavailable');
      this.save({ ...this.state, pending: this.state.pending.filter(entry => entry.id !== id),
        agents: [...this.state.agents, agent] });
    } finally { this.claims.delete(id); }
  }

  async heartbeat(id, token, host) {
    const agent = this.authorizedAgent(id, token);
    if (!agent || !isPublicAddress(host)) throw new Error('Agent is unavailable');
    if (host !== agent.host) await this.probe({ ...agent, host });
    if (!this.authorizedAgent(id, token)) throw new Error('Agent is unavailable');
    this.save({ ...this.state, agents: this.state.agents.map(entry => entry.id === id ?
      { ...entry, host, lastSeen: this.now() } : entry) });
  }

  async handle(socket, hello, administrator) {
    const management = hello.mode === 'manage' && administrator;
    const enrollment = hello.mode === 'enroll' && this.canEnroll(hello.id, hello.code);
    const agent = hello.mode === 'agent' && this.authorizedAgent(hello.id, hello.token);
    if (!management && !enrollment && !agent) {
      writeFrame(socket, { code: 'AUTH' }); socket.end(); return;
    }
    writeFrame(socket, { code: 'OK' });
    try {
      const request = await readFrame(socket, FRAME_LIMIT);
      if (management && request.action === 'create') {
        writeFrame(socket, { code: 'OK', ...this.issue(request.name, request.port) }, FRAME_LIMIT);
      } else if (management && request.action === 'list') {
        const agents = this.list();
        writeFrame(socket, { code: 'OK', count: agents.length });
        for (const entry of agents) writeFrame(socket, entry, FRAME_LIMIT);
      } else if (management && request.action === 'remove') {
        this.remove(request.id); writeFrame(socket, { code: 'OK' });
      } else if (enrollment && request.action === 'enroll') {
        await this.enroll(hello.id, hello.code, request);
        writeFrame(socket, { code: 'OK' });
      } else if (agent && request.action === 'heartbeat') {
        await this.heartbeat(hello.id, hello.token, request.host);
        writeFrame(socket, { code: 'OK' });
      } else writeFrame(socket, { code: 'INVALID' });
    } catch {
      if (!socket.destroyed) writeFrame(socket, { code: 'FAILED' });
    } finally { socket.end(); }
  }
}
