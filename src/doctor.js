import net, { isIP } from 'node:net';
import tls, { checkServerIdentity } from 'node:tls';
import { lookup } from 'node:dns/promises';
import { performance } from 'node:perf_hooks';
import { validateDestination } from './policy.js';

const hints = new Map([
  ['ENOTFOUND', 'hostname not found; check DNS records'],
  ['EAI_AGAIN', 'DNS lookup timed out; try another resolver or check connectivity'],
  ['ECONNREFUSED', 'connection refused; check the service and exposed port'],
  ['ETIMEDOUT', 'connection timed out; check host and provider firewalls'],
  ['ECONNRESET', 'connection reset by the remote endpoint'],
  ['CERT_HAS_EXPIRED', 'certificate has expired'],
  ['DEPTH_ZERO_SELF_SIGNED_CERT', 'certificate is self-signed or its CA is not trusted'],
  ['SELF_SIGNED_CERT_IN_CHAIN', 'certificate chain contains an untrusted self-signed certificate'],
  ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'certificate chain is incomplete or untrusted'],
  ['ERR_TLS_CERT_ALTNAME_INVALID', 'certificate does not cover this hostname'],
  ['ERR_SSL_WRONG_VERSION_NUMBER', 'endpoint did not negotiate TLS on this port'],
]);

function elapsed(started) {
  return Math.max(0, Math.round(performance.now() - started));
}

function timeoutError() {
  const error = new Error('Timed out');
  error.code = 'ETIMEDOUT';
  return error;
}

function errorDetail(error) {
  const code = typeof error?.code === 'string' ? error.code : 'UNKNOWN';
  return { code, detail: hints.get(code) ?? `unexpected network error (${code})` };
}

async function resolveHost(host, timeout, resolver) {
  if (isIP(host)) return [{ address: host, family: isIP(host) }];
  let timer;
  try {
    const addresses = await Promise.race([
      resolver(host, { all: true, verbatim: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(timeoutError()), timeout); }),
    ]);
    return [...new Map(addresses.map((entry) => [`${entry.family}:${entry.address}`, entry])).values()];
  } finally {
    clearTimeout(timer);
  }
}

function openTcp(host, addresses, port, timeout) {
  return new Promise((resolve, reject) => {
    const useResolvedAddresses = (_hostname, options, callback) => {
      if (options.all) callback(null, addresses);
      else callback(null, addresses[0].address, addresses[0].family);
    };
    const socket = net.connect({ host, port, lookup: useResolvedAddresses,
      autoSelectFamily: true, autoSelectFamilyAttemptTimeout: 250 });
    const timer = setTimeout(() => socket.destroy(timeoutError()), timeout);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('connect', ready);
      socket.off('error', failed);
    };
    const ready = () => {
      cleanup();
      socket.on('error', () => {});
      resolve({ socket, family: socket.remoteFamily === 'IPv6' ? 6 : 4 });
    };
    const failed = (error) => {
      cleanup();
      socket.destroy();
      reject(error);
    };
    socket.once('connect', ready);
    socket.once('error', failed);
  });
}

function openTls(socket, host, ca, timeout) {
  return new Promise((resolve, reject) => {
    const identity = host.replace(/\.$/, '');
    const servername = isIP(host) ? undefined : identity;
    const secure = tls.connect({ socket, servername, ca, rejectUnauthorized: true,
      minVersion: 'TLSv1.3' });
    const timer = setTimeout(() => secure.destroy(timeoutError()), timeout);
    const cleanup = () => {
      clearTimeout(timer);
      secure.off('secureConnect', ready);
      secure.off('error', failed);
    };
    const failed = (error) => {
      cleanup();
      secure.destroy();
      reject(error);
    };
    const ready = () => {
      const certificate = secure.getPeerCertificate();
      const identityError = checkServerIdentity(identity, certificate);
      if (identityError) {
        failed(identityError);
        return;
      }
      cleanup();
      resolve({ socket: secure, certificate, protocol: secure.getProtocol() });
    };
    secure.once('secureConnect', ready);
    secure.once('error', failed);
  });
}

export async function diagnoseEndpoint({ host, port = 443, ca, timeout = 10_000,
  resolver = lookup }) {
  validateDestination(host, port);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 120000) throw new Error('Invalid diagnostic timeout');
  const endpoint = isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
  const checks = [];
  let addresses;
  let started = performance.now();
  try {
    addresses = await resolveHost(host, timeout, resolver);
    if (!addresses.length) throw Object.assign(new Error('No addresses'), { code: 'ENOTFOUND' });
    const families = [...new Set(addresses.map(({ family }) => `IPv${family}`))].join(', ');
    checks.push({ name: 'dns', status: 'pass', durationMs: elapsed(started),
      detail: `${addresses.length} address${addresses.length === 1 ? '' : 'es'} (${families})` });
  } catch (error) {
    checks.push({ name: 'dns', status: 'fail', durationMs: elapsed(started), ...errorDetail(error) });
    checks.push({ name: 'tcp', status: 'skip', detail: 'blocked by DNS failure' });
    checks.push({ name: 'tls', status: 'skip', detail: 'blocked by DNS failure' });
    return { version: 1, endpoint, ok: false, checks };
  }

  let socket;
  started = performance.now();
  try {
    const connected = await openTcp(host, addresses, port, timeout);
    socket = connected.socket;
    checks.push({ name: 'tcp', status: 'pass', durationMs: elapsed(started),
      detail: `connection accepted via IPv${connected.family}` });
  } catch (error) {
    checks.push({ name: 'tcp', status: 'fail', durationMs: elapsed(started), ...errorDetail(error) });
    checks.push({ name: 'tls', status: 'skip', detail: 'blocked by TCP failure' });
    return { version: 1, endpoint, ok: false, checks };
  }

  started = performance.now();
  try {
    const result = await openTls(socket, host, ca, timeout);
    const expires = new Date(result.certificate.valid_to);
    const validity = Number.isNaN(expires.valueOf()) ? '' : `; expires ${expires.toISOString()}`;
    checks.push({ name: 'tls', status: 'pass', durationMs: elapsed(started),
      detail: `${result.protocol}; certificate trusted for ${host}${validity}` });
    result.socket.destroy();
  } catch (error) {
    socket.destroy();
    checks.push({ name: 'tls', status: 'fail', durationMs: elapsed(started), ...errorDetail(error) });
    return { version: 1, endpoint, ok: false, checks };
  }
  return { version: 1, endpoint, ok: true, checks };
}

export function formatDiagnosis(report) {
  const lines = ['ETL doctor', `Endpoint  ${report.endpoint}`, ''];
  for (const check of report.checks) {
    const duration = check.durationMs === undefined ? '' : ` (${check.durationMs} ms)`;
    lines.push(`[${check.status.padEnd(4)}] ${check.name.toUpperCase().padEnd(4)} ${check.detail}${duration}`);
  }
  lines.push('', report.ok
    ? 'Result    ready: verified TLS 1.3 endpoint; no credentials were sent.'
    : 'Result    not ready: fix the first failed check, then run doctor again.');
  return lines.join('\n');
}
