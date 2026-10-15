// Minimal SMTP sink for the gate e2e: captures the magic-link mail line by line on 28097,
// hands it to the spec at /last (and /reset between specs).
let body = '';

type conn = { inData: boolean; buf: string; msg: string };
const conns = new Map<any, conn>();

Bun.listen({
  hostname: '127.0.0.1',
  port: 28097,
  socket: {
    open(socket) {
      conns.set(socket, { inData: false, buf: '', msg: '' });
      socket.write('220 mock ESMTP\r\n');
    },
    data(socket, chunk) {
      const c = conns.get(socket);
      if (!c) return;
      c.buf += String(chunk);
      let nl;
      while ((nl = c.buf.indexOf('\r\n')) >= 0) {
        const line = c.buf.slice(0, nl);
        c.buf = c.buf.slice(nl + 2);
        if (c.inData) {
          if (line === '.') {
            c.inData = false;
            body = c.msg;
            c.msg = '';
            socket.write('250 OK\r\n');
          } else {
            c.msg = c.msg === '' ? line : c.msg + '\n' + line;
          }
          continue;
        }
        const up = line.toUpperCase();
        if (up.startsWith('EHLO')) {
          socket.write('250-mock\r\n250 OK\r\n');
        } else if (up === 'DATA') {
          c.inData = true;
          socket.write('354 go\r\n');
        } else if (up === 'QUIT') {
          socket.write('221 bye\r\n');
          socket.end();
        } else {
          socket.write('250 OK\r\n');
        }
      }
    },
  },
});

Bun.serve({
  port: 28098,
  hostname: '127.0.0.1',
  fetch(req) {
    const u = new URL(req.url);
    if (u.pathname === '/ping') return new Response('ok');
    if (u.pathname === '/reset') {
      body = '';
      return new Response('ok');
    }
    if (u.pathname === '/last') return new Response(body, { status: body ? 200 : 404 });
    return new Response(null, { status: 404 });
  },
});