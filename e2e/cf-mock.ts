// Minimal Cloudflare API mock for e2e. Zones named "missing.*" are not found.
const ok = (result: unknown, extra = {}) =>
  Response.json({ success: true, errors: [], messages: [], result, ...extra });

Bun.serve({
  port: 28099,
  hostname: '127.0.0.1',
  fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/user/tokens/verify') return ok({ id: 'tok', status: 'active' });
    if (url.pathname === '/zones') {
      const name = url.searchParams.get('name') ?? '';
      const zones = name.startsWith('missing.') ? [] : [{ id: `zone-${name}`, name }];
      return ok(zones, { result_info: { page: 1, per_page: 20, count: zones.length, total_count: zones.length } });
    }
    return new Response('not mocked', { status: 404 });
  },
});
