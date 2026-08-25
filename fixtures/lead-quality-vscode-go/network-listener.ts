import * as net from 'net';

export function waitForDebugPeer(port: number, timeoutMs: number): Promise<net.Socket> {
  let server: net.Server;
  return new Promise((resolve, reject) => {
    server = net.createServer({ pauseOnConnect: true }, (socket) => {
      clearTimeout(timer);
      server.close();
      resolve(socket);
    });
    const timer = setTimeout(() => {
      server.close();
      reject(new Error('Timed out waiting for the intended debug peer'));
    }, timeoutMs);
    server.listen(port);
  });
}

export function explicitLoopbackControl(port: number): net.Server {
  const server = net.createServer();
  server.listen(port, '127.0.0.1');
  return server;
}

export function unprovenFactoryControl(factory: { createServer(): net.Server }, port: number): net.Server {
  const server = factory.createServer();
  server.listen(port);
  return server;
}
