// Minimal stateful Cloudflare API mock for e2e. Zones named "missing.*" are not found.
type Rec = { id: string; name: string; content: string; type: 'A'; proxied: boolean; comment: string; ttl: number };

const records = new Map<string, Rec>();
let seq = 0;

const ok = (result: unknown, extra = {}) =>
  Response.json({ success: true, errors: [], messages: [], result, ...extra });
const info = (n: number) => ({ result_info: { page: 1, per_page: 100, count: n, total_count: n } });

Bun.serve({
  port: 28099,
  hostname: '127.0.0.1',
  async fetch(req) {
    const url = new URL(req.url);
    const parts = url.pathname.split('/').filter(Boolean);
    if (url.pathname === '/user/tokens/verify') return ok({ id: 'tok', status: 'active' });
    if (url.pathname === '/zones') {
      const name = url.searchParams.get('name') ?? '';
      const zones = name.startsWith('missing.') ? [] : [{ id: `zone-${name}`, name }];
      return ok(zones, info(zones.length));
    }
    if (parts[0] === 'zones' && parts[2] === 'dns_records') {
      const id = parts[3];
      if (req.method === 'GET' && !id) {
        const name = (url.searchParams.get('name.exact') ?? url.searchParams.get('name') ?? '').toLowerCase();
        const hits = [...records.values()].filter((r) => r.name.toLowerCase() === name);
        return ok(hits, info(hits.length));
      }
      if (req.method === 'POST' && !id) {
        const b = await req.json();
        const rec: Rec = { id: `rec${++seq}`, type: 'A', ttl: 1, name: b.name, content: b.content, proxied: !!b.proxied, comment: b.comment ?? '' };
        records.set(rec.id, rec);
        return ok(rec);
      }
      if ((req.method === 'PUT' || req.method === 'PATCH') && id) {
        const cur = records.get(id);
        if (!cur) return Response.json({ success: false, errors: [{ code: 81044, message: 'Record does not exist.' }], messages: [], result: null }, { status: 404 });
        const b = await req.json();
        const rec = { ...cur, name: b.name, content: b.content };
        records.set(id, rec);
        return ok(rec);
      }
      if (req.method === 'DELETE' && id) {
        records.delete(id);
        return ok({ id });
      }
    }
    return new Response('not mocked', { status: 404 });
  },
});
