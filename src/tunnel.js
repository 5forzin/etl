import net from 'node:net';
import tls from 'node:tls';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { read, readFrame, writeFrame, protect, connected, relay, track } from './io.js';
import { resolveDestination, validateDestination } from './policy.js';
import { httpDestination, httpReply } from './http-proxy.js';

const HANDSHAKE = 10_000;
const IDLE = 120_000;
const hash = (value) => createHash('sha256').update(value).digest();

function validateLimits(maxConnections, handshakeTimeout, idleTimeout) {
  for (const [name, value, maximum] of [['maxConnections', maxConnections, 10000],
    ['handshakeTimeout', handshakeTimeout, 120000], ['idleTimeout', idleTimeout, 86400000]]) {
    if (!Number.isInteger(value) || value < 1 || value > maximum) {
      throw new Error(`${name} must be between 1 and ${maximum}`);
    }
  }
}

export function validateToken(token) {
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) {
    throw new Error('Token must be 64 lowercase hex characters; use etl token');
  }
  return token;
}

// Reload on every authentication so replacement revokes future connections.
export function tokenFile(path) {
  validateToken(readFileSync(path, 'utf8').trim());
  return () => validateToken(readFileSync(path, 'utf8').trim());
}

export function createTunnelServer({ key, cert, getToken, maxConnections = 128,
  handshakeTimeout = HANDSHAKE, idleTimeout = IDLE,
  resolve = resolveDestination }) {
  validateLimits(maxConnections, handshakeTimeout, idleTimeout);
  validateToken(getToken());
  const server = tls.createServer({ key, cert, minVersion: 'TLSv1.3',
    handshakeTimeout, allowHalfOpen: true }, (socket) => {
    protect(socket, handshakeTimeout);
    const deadline = setTimeout(() => socket.destroy(), handshakeTimeout);
    let target;
    socket.once('close', () => { clearTimeout(deadline); target?.destroy(); });
    void (async () => {
      const hello = await readFrame(socket);
      if (hello?.v !== 1 || typeof hello.token !== 'string' ||
          !timingSafeEqual(hash(hello.token), hash(getToken()))) {
        writeFrame(socket, { code: 'AUTH' });
        socket.end();
        return;
      }
      writeFrame(socket, { code: 'OK' });
      const request = await readFrame(socket);
      const addresses = await resolve(request?.host, request?.port);
      if (socket.destroyed) return;
      for (const { address, family } of addresses) {
        if (socket.destroyed) return;
        target = protect(net.connect({ host: address, port: request.port,
          family, allowHalfOpen: true }), handshakeTimeout);
        try { await connected(target); break; }
        catch { target.destroy(); target = undefined; }
      }
      if (!target || socket.destroyed) throw new Error('Connection failed');
      clearTimeout(deadline);
      writeFrame(socket, { code: 'OK' });
      relay(socket, target, idleTimeout);
    })().catch(() => {
      target?.destroy();
      if (!socket.destroyed) {
        writeFrame(socket, { code: 'FAILED' });
        socket.end();
      }
    });
  });
  server.maxConnections = maxConnections;
  server.on('tlsClientError', () => {});
  return track(server);
}

async function socksDestination(socket, firstByte) {
  const greeting = Buffer.from([firstByte, (await read(socket, 1))[0]]);
  if (greeting[0] !== 5 || greeting[1] === 0) throw new Error('Invalid SOCKS greeting');
  const methods = await read(socket, greeting[1]);
  if (!methods.includes(0)) {
    socket.end(Buffer.from([5, 255]));
    return null;
  }
  socket.write(Buffer.from([5, 0]));
  const header = await read(socket, 4);
  if (header[0] !== 5 || header[2] !== 0) throw new Error('Invalid SOCKS request');
  if (header[1] !== 1) { reply(socket, 7); socket.end(); return null; }
  let host;
  if (header[3] === 1) host = [...await read(socket, 4)].join('.');
  else if (header[3] === 3) {
    const length = (await read(socket, 1))[0];
    if (!length) throw new Error('Empty hostname');
    host = (await read(socket, length)).toString('utf8');
  } else if (header[3] === 4) {
    const bytes = await read(socket, 16);
    host = Array.from({ length: 8 }, (_, i) => bytes.readUInt16BE(i * 2).toString(16)).join(':');
  } else { reply(socket, 8); socket.end(); return null; }
  const port = (await read(socket, 2)).readUInt16BE();
  validateDestination(host, port);
  return { host, port };
}

function reply(socket, code) {
  socket.write(Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]));
}

export function createClient({ host, port = 443, servername = host, token, ca,
  fallbacks = [], connectTimeout = 1000,
  maxConnections = 128, handshakeTimeout = HANDSHAKE, idleTimeout = IDLE }) {
  validateLimits(maxConnections, handshakeTimeout, idleTimeout);
  validateToken(token);
  if (!Number.isInteger(connectTimeout) || connectTimeout < 1 || connectTimeout > 60_000) {
    throw new Error('connectTimeout must be between 1 and 60000 milliseconds');
  }
  const endpoints = [{ host, port, servername, token }, ...fallbacks.map((endpoint) => ({
    host: endpoint.host, port: endpoint.port ?? port,
    servername: endpoint.servername ?? endpoint.host, token: endpoint.token ?? token,
  }))];
  for (const endpoint of endpoints) {
    validateToken(endpoint.token);
    if (typeof endpoint.host !== 'string' || !endpoint.host ||
        !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) {
      throw new Error('Invalid tunnel endpoint');
    }
  }
  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    protect(socket, handshakeTimeout);
    let deadline = setTimeout(() => socket.destroy(), handshakeTimeout);
    let tunnel;
    let isHttp = false;
    socket.once('close', () => { clearTimeout(deadline); tunnel?.destroy(); });
    void (async () => {
      const firstByte = (await read(socket, 1))[0];
      isHttp = firstByte !== 5;
      const destination = isHttp ? await httpDestination(socket, firstByte) :
        await socksDestination(socket, firstByte);
      if (!destination || socket.destroyed) return;
      clearTimeout(deadline);
      const setupTimeout = handshakeTimeout + endpoints.length * connectTimeout;
      socket.setTimeout(setupTimeout);
      deadline = setTimeout(() => socket.destroy(), setupTimeout);
      for (const endpoint of endpoints) {
        if (socket.destroyed) return;
        const candidate = protect(tls.connect({ host: endpoint.host, port: endpoint.port,
          servername: endpoint.servername, ca, rejectUnauthorized: true,
          minVersion: 'TLSv1.3', allowHalfOpen: true }), connectTimeout);
        tunnel = candidate;
        // One absolute budget covers DNS, TCP, TLS and authentication, even if
        // a stalled endpoint sends occasional bytes. No application data is retried.
        const attemptDeadline = setTimeout(() => candidate.destroy(), connectTimeout);
        try {
          await connected(candidate, 'secureConnect');
          if (socket.destroyed) { candidate.destroy(); return; }
          writeFrame(candidate, { v: 1, token: endpoint.token });
          if ((await readFrame(candidate))?.code !== 'OK') throw new Error('Authentication failed');
          candidate.setTimeout(handshakeTimeout);
          break;
        } catch {
          candidate.destroy();
          tunnel = undefined;
        } finally {
          clearTimeout(attemptDeadline);
        }
      }
      if (!tunnel || socket.destroyed) throw new Error('No tunnel endpoint available');
      writeFrame(tunnel, destination);
      if ((await readFrame(tunnel))?.code !== 'OK') throw new Error('Destination failed');
      clearTimeout(deadline);
      if (isHttp) httpReply(socket, true);
      else reply(socket, 0);
      relay(socket, tunnel, idleTimeout);
    })().catch(() => {
      tunnel?.destroy();
      if (!socket.destroyed) {
        if (isHttp) httpReply(socket, false);
        else reply(socket, 1);
        socket.end();
      }
    });
  });
  server.maxConnections = maxConnections;
  return track(server);
}
