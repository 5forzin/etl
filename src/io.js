// Read exactly n bytes without consuming pipelined application data.
export async function read(socket, n) {
  const chunks = [];
  let remaining = n;
  while (remaining > 0) {
    const available = Math.min(remaining, socket.readableLength);
    const bytes = available > 0 ? socket.read(available) : null;
    if (bytes !== null) {
      chunks.push(bytes);
      remaining -= bytes.length;
      continue;
    }
    if (socket.destroyed || socket.readableEnded) throw new Error('Connection closed');
    await new Promise((resolve, reject) => {
      const cleanup = () => {
        socket.off('readable', ready);
        socket.off('end', closed);
        socket.off('close', closed);
        socket.off('error', failed);
      };
      const ready = () => { cleanup(); resolve(); };
      const closed = () => { cleanup(); reject(new Error('Connection closed')); };
      const failed = (error) => { cleanup(); reject(error); };
      socket.once('readable', ready);
      socket.once('end', closed);
      socket.once('close', closed);
      socket.once('error', failed);
    });
  }
  return Buffer.concat(chunks, n);
}

export async function readFrame(socket) {
  const length = (await read(socket, 2)).readUInt16BE();
  if (length < 2 || length > 1024) throw new Error('Invalid frame size');
  return JSON.parse((await read(socket, length)).toString('utf8'));
}

export function writeFrame(socket, message) {
  const payload = Buffer.from(JSON.stringify(message));
  if (payload.length > 1024) throw new Error('Frame too large');
  const length = Buffer.alloc(2);
  length.writeUInt16BE(payload.length);
  socket.write(Buffer.concat([length, payload]));
}

export function protect(socket, timeout) {
  // Keep errors handled even between protocol phases.
  socket.on('error', () => {});
  socket.setTimeout(timeout, () => socket.destroy());
  return socket;
}

export async function connected(socket, event = 'connect') {
  await new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.off(event, ready);
      socket.off('error', failed);
      socket.off('close', closed);
    };
    const ready = () => { cleanup(); resolve(); };
    const failed = (error) => { cleanup(); reject(error); };
    const closed = () => { cleanup(); reject(new Error('Connection closed')); };
    socket.once(event, ready);
    socket.once('error', failed);
    socket.once('close', closed);
  });
  return socket;
}

export function relay(a, b, idleTimeout) {
  a.setTimeout(idleTimeout);
  b.setTimeout(idleTimeout);
  a.on('error', () => b.destroy());
  b.on('error', () => a.destroy());
  a.on('close', () => b.destroy());
  b.on('close', () => a.destroy());
  a.pipe(b);
  b.pipe(a);
}

export function track(server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.shutdown = () => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    for (const socket of sockets) socket.destroy();
  });
  return server;
}
