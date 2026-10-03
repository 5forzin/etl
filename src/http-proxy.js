import { read } from './io.js';
import { validateDestination } from './policy.js';

// Read only the header: bytes queued after CONNECT belong to the application.
export async function httpDestination(socket, firstByte) {
  const bytes = [firstByte];
  while (bytes.length < 16_384) {
    const byte = (await read(socket, 1))[0];
    if (byte !== 9 && byte !== 10 && byte !== 13 && (byte < 32 || byte > 126)) {
      throw new Error('Invalid HTTP header');
    }
    bytes.push(byte);
    if (bytes.length >= 4 && bytes.slice(-4).join(',') === '13,10,13,10') break;
  }
  if (bytes.slice(-4).join(',') !== '13,10,13,10') throw new Error('HTTP header too large');
  const [line, ...headers] = Buffer.from(bytes).toString('ascii').slice(0, -4).split('\r\n');
  const match = /^CONNECT (\[[0-9a-f:]+\]|[a-z0-9.-]+):([0-9]{1,5}) HTTP\/1\.[01]$/i.exec(line);
  if (!match || headers.some((header) => !/^[!#$%&'*+.^_`|~0-9a-z-]+:[\t\x20-\x7e]*$/i.test(header))) {
    throw new Error('Expected HTTP CONNECT');
  }
  // A CONNECT request has no body. Reject ambiguous framing rather than forwarding it.
  if (headers.some((h) => /^transfer-encoding:/i.test(h) ||
      (/^content-length:/i.test(h) && !/^content-length:\s*0\s*$/i.test(h)))) {
    throw new Error('CONNECT body is not supported');
  }
  const host = match[1].replace(/^\[|\]$/g, '');
  const port = Number(match[2]);
  validateDestination(host, port);
  return { host, port };
}

export function httpReply(socket, success) {
  socket.write(success ? 'HTTP/1.1 200 Connection Established\r\n\r\n' :
    'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
}
