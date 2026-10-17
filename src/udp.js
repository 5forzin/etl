import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { read, readFrame, writeFrame, protect, connected } from './io.js';
import { resolveDestination, validateDestination } from './policy.js';

export const MAX_DATAGRAM = 1500;

export function validateUdpLimits(maxDestinations, maxDatagram) {
  for (const [name, value, maximum] of [['maxDestinations', maxDestinations, 10000],
    ['maxDatagram', maxDatagram, 65507]]) {
    if (!Number.isInteger(value) || value < 1 || value > maximum) {
      throw new Error(`${name} must be between 1 and ${maximum}`);
    }
  }
}

// A datagram is a {host, port} frame followed by a 16-bit length and the
// payload. Control frames ({code}) share the framing so a rejected
// destination can drop one datagram without killing the session.
export function writeDatagram(socket, host, port, payload) {
  writeFrame(socket, { host, port });
  const length = Buffer.alloc(2);
  length.writeUInt16BE(payload.length);
  socket.write(Buffer.concat([length, payload]));
}

export async function readDatagram(socket, maxDatagram) {
  const header = await readFrame(socket);
  if (typeof header.code === 'string' && header.host === undefined) {
    return { code: header.code };
  }
  if (typeof header.host !== 'string' || !Number.isInteger(header.port) ||
      header.port < 1 || header.port > 65535) throw new Error('Invalid datagram header');
  const length = (await read(socket, 2)).readUInt16BE();
  if (length < 1 || length > maxDatagram) throw new Error('Invalid datagram length');
  return { host: header.host, port: header.port, payload: await read(socket, length) };
}

export function parseUdpPacket(buffer) {
  if (buffer.length < 4 || buffer[0] !== 0 || buffer[1] !== 0 || buffer[2] !== 0) return null;
  let offset = 3;
  const type = buffer[offset++];
  let host;
  if (type === 1) {
    if (buffer.length < offset + 6) return null;
    host = [...buffer.subarray(offset, offset + 4)].join('.');
    offset += 4;
  } else if (type === 3) {
    const size = buffer[offset++];
    if (!size || buffer.length < offset + size + 2) return null;
    host = buffer.subarray(offset, offset + size).toString('utf8');
    offset += size;
  } else if (type === 4) {
    if (buffer.length < offset + 18) return null;
    host = Array.from({ length: 8 }, (_, i) =>
      buffer.readUInt16BE(offset + i * 2).toString(16)).join(':');
    offset += 16;
  } else return null;
  if (buffer.length < offset + 2) return null;
  return { host, port: buffer.readUInt16BE(offset), payload: buffer.subarray(offset + 2) };
}

// Expand a textual IPv6 address (including "::" compression) to 16 bytes.
// IPv4-mapped forms never appear: the destination policy blocks them.
function ipv6Bytes(host) {
  const sections = host.split('::');
  if (sections.length > 2) return null;
  const parse = (section) => section === '' ? [] : section.split(':').map((group) =>
    /^[0-9a-fA-F]{1,4}$/.test(group) ? parseInt(group, 16) : null);
  const head = parse(sections[0]);
  const tail = sections.length === 2 ? parse(sections[1]) : [];
  if (head.includes(null) || tail.includes(null)) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (sections.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(missing).fill(0), ...tail];
  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) => bytes.writeUInt16BE(group, index * 2));
  return bytes;
}

export function buildUdpPacket(host, port, payload) {
  const type = net.isIPv4(host) ? 1 : net.isIPv6(host) ? 4 : 3;
  const address = type === 1 ? Buffer.from(host.split('.').map(Number)) :
    type === 4 ? ipv6Bytes(host) :
    Buffer.concat([Buffer.from([Buffer.byteLength(host)]), Buffer.from(host)]);
  if (!address || address.length > 255) return null;
  const header = Buffer.alloc(4 + address.length + 2);
  header[3] = type;
  address.copy(header, 4);
  header.writeUInt16BE(port, 4 + address.length);
  return Buffer.concat([header, payload]);
}

// Server side of a v2 UDP session: one TLS connection relaying datagrams to
// validated destinations, one socket per destination, LRU-evicted.
export function createUdpRelay({ resolve = resolveDestination, idleTimeout = 120_000,
  maxDestinations = 64, maxDatagram = MAX_DATAGRAM } = {}) {
  validateUdpLimits(maxDestinations, maxDatagram);
  return async function udpRelay(socket) {
    const destinations = new Map();
    const closeDestination = (key, entry) => {
      if (destinations.get(key) !== entry) return;
      destinations.delete(key);
      try { entry.socket.close(); } catch { /* Already closed. */ }
    };
    const stop = () => {
      for (const [key, entry] of destinations) closeDestination(key, entry);
    };
    socket.once('close', stop);
    try {
      for (;;) {
        const datagram = await readDatagram(socket, maxDatagram);
        if (datagram.code) throw new Error('Unexpected control frame');
        const key = `${datagram.host.toLowerCase()}:${datagram.port}`;
        let entry = destinations.get(key);
        if (!entry) {
          validateDestination(datagram.host, datagram.port);
          let addresses;
          try { addresses = await resolve(datagram.host, datagram.port); }
          catch {
            writeFrame(socket, { code: 'FAILED' });
            continue;
          }
          const address = addresses[0];
          const target = dgram.createSocket(address.family === 6 ? 'udp6' : 'udp4');
          entry = { socket: target, address: address.address, port: datagram.port };
          target.on('message', (payload, rinfo) => {
            if (payload.length > maxDatagram) return;
            writeDatagram(socket, rinfo.address, rinfo.port, payload);
          });
          target.on('error', () => closeDestination(key, entry));
          target.on('close', () => closeDestination(key, entry));
          if (destinations.size >= maxDestinations) {
            const [oldest] = destinations.keys();
            closeDestination(oldest, destinations.get(oldest));
          }
          destinations.set(key, entry);
        } else {
          destinations.delete(key);
          destinations.set(key, entry);
        }
        entry.socket.send(datagram.payload, entry.port, entry.address, () => {});
      }
    } catch { /* The client closed the session or violated the framing. */ }
    finally { stop(); socket.destroy(); }
  };
}

// Client side of a v2 UDP session: TLS 1.3, {v:2, mode:"udp"} hello, then
// framed datagrams. Resolves with an emitter exposing send() and destroy().
export async function openUdpSession({ host, port, servername = host, token, ca,
  connectTimeout = 5000, idleTimeout = 120_000, maxDatagram = MAX_DATAGRAM }) {
  validateUdpLimits(1, maxDatagram);
  const socket = protect(tls.connect({ host, port, servername, ca,
    rejectUnauthorized: true, minVersion: 'TLSv1.3' }), connectTimeout);
  const deadline = setTimeout(() => socket.destroy(), connectTimeout);
  const session = new EventEmitter();
  try {
    await connected(socket, 'secureConnect');
    writeFrame(socket, { v: 2, token, mode: 'udp' });
    if ((await readFrame(socket))?.code !== 'OK') throw new Error('UDP sessions unsupported');
  } catch (error) {
    socket.destroy();
    throw error;
  } finally {
    clearTimeout(deadline);
  }
  socket.setTimeout(idleTimeout, () => socket.destroy());
  session.send = (host, port, payload) => writeDatagram(socket, host, port, payload);
  session.destroy = () => socket.destroy();
  void (async () => {
    try {
      for (;;) {
        const datagram = await readDatagram(socket, maxDatagram);
        if (!datagram.code) session.emit('datagram', datagram);
      }
    } catch { /* Idle timeout, server shutdown or a closed socket. */ }
    finally { socket.destroy(); session.emit('close'); }
  })();
  return session;
}
