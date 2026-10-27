'use strict';
// Pawfect Homes – Node server using Supabase (Postgres + Storage). Built by Nemath & Tanaaz
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const SB = (process.env.SUPABASE_URL || '').replace(/\/+$/, ''), KEY = process.env.SUPABASE_SERVICE_KEY || '';
if (!SB || !KEY) { console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables.'); process.exit(1); }
const PUB = path.join(__dirname, 'public');
const AUTH = { apikey: KEY, ...(KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + KEY } : {}) };
const q = encodeURIComponent;

// ---------- Supabase helpers ----------
async function rest(method, pq, body) {
  const r = await fetch(SB + '/rest/v1/' + pq, { method, headers: { ...AUTH, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text();
  if (!r.ok) { const e = new Error('db ' + r.status + ': ' + t.slice(0, 300)); e.body = t; throw e; }
  return t ? JSON.parse(t) : null;
}
async function saveImg(s) {
  if (typeof s !== 'string' || s.length > 700000) return null;
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(s); if (!m) return null;
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length > 500e3 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  const name = rid() + '.jpg';
  const r = await fetch(`${SB}/storage/v1/object/pets/${name}`, { method: 'POST', headers: { ...AUTH, 'Content-Type': 'image/jpeg' }, body: buf });
  if (!r.ok) { console.error('upload failed', r.status, (await r.text()).slice(0, 200)); return null; }
  return `${SB}/storage/v1/object/public/pets/${name}`;
}
const delImg = url => { if (url && url.startsWith(SB + '/storage/')) fetch(`${SB}/storage/v1/object/pets/${path.basename(url)}`, { method: 'DELETE', headers: AUTH }).catch(() => {}); };

// ---------- general helpers ----------
const rid = () => crypto.randomBytes(8).toString('hex');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k)));
const S = (v, n) => typeof v === 'string' ? v.trim().slice(0, n) : '';
const hits = new Map();
function limited(key, max, ms) { const n = Date.now(); let h = hits.get(key); if (!h || h.r < n) { h = { c: 0, r: n + ms }; hits.set(key, h); } return ++h.c > max; }
setInterval(() => { const n = Date.now(); for (const [k, h] of hits) if (h.r < n) hits.delete(k); }, 600000).unref();
const secure = req => req.headers['x-forwarded-proto'] === 'https';
const ipOf = req => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;
const cookie = (req, n) => { const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(n + '=')); return m ? m.slice(n.length + 1) : null; };
async function startSession(req, res, uid) {
  const tok = crypto.randomBytes(32).toString('hex');
  await rest('POST', 'sessions', { token_hash: sha(tok), uid, exp: new Date(Date.now() + 30 * 864e5).toISOString() });
  res.setHeader('Set-Cookie', `pp_sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${secure(req) ? '; Secure' : ''}`);
}
async function userOf(req) {
  const t = cookie(req, 'pp_sid'); if (!t) return null;
  try {
    const r = await rest('GET', `sessions?token_hash=eq.${sha(t)}&select=exp,users(id,name,email,favs)`);
    const s = r && r[0]; if (!s || !s.users || Date.parse(s.exp) < Date.now()) return null; return s.users;
  } catch (e) { console.error(e.message); return null; }
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const bad = (res, m, c = 400) => send(res, c, { error: m });
function readBody(req, max = 3e6) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', d => { n += d.length; if (n > max) { no(new Error('That upload is too large')); req.destroy(); } else ch.push(d); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(ch).toString() || '{}')); } catch (e) { no(new Error('Bad request')); } });
    req.on('error', no);
  });
}
const CATS = ['cat', 'dog', 'rabbit', 'bird', 'other'];
const pub = (p, u) => ({ id: p.id, n: p.n, c: p.c, g: p.g, t: p.t, p: p.p, a: p.a, w: p.w, l: p.l, d: p.d, img: p.img, by: (p.users || {}).name || 'Someone', dt: p.at, mine: !!u && u.id === p.uid });

// ---------- API ----------
async function api(req, res, p) {
  const m = req.method, u = await userOf(req), ip = ipOf(req), parts = p.split('/').filter(Boolean), r0 = parts[0];
  if (m !== 'GET') {
    if (!(req.headers['content-type'] || '').includes('application/json')) return bad(res, 'Bad request');
    const o = req.headers.origin; if (o) { try { if (new URL(o).host !== req.headers.host) return bad(res, 'Bad origin', 403); } catch (e) { return bad(res, 'Bad origin', 403); } }
  }
  let b = {}; if (m === 'POST') { try { b = await readBody(req); } catch (e) { return bad(res, e.message, 413); } }
  const need = () => { if (!u) { bad(res, 'Please sign in first', 401); return true; } };

  if (m === 'POST' && (r0 === 'signup' || r0 === 'login')) {
    if (limited('a' + ip, 15, 9e5)) return bad(res, 'Too many attempts – try again in a few minutes', 429);
    const email = S(b.email, 120).toLowerCase(), pw = typeof b.password === 'string' ? b.password : '';
    if (!/^\S+@\S+\.\S+$/.test(email) || pw.length < 8 || pw.length > 200) return bad(res, 'Enter a valid email and a password of 8+ characters');
    const found = (await rest('GET', `users?email=eq.${q(email)}&select=id,name,salt,hash`))[0];
    if (r0 === 'signup') {
      const name = S(b.name, 30); if (!name) return bad(res, 'Please add your name');
      if (found) return bad(res, 'That email already has an account');
      const salt = crypto.randomBytes(16), id = rid();
      try { await rest('POST', 'users', { id, name, email, salt: salt.toString('hex'), hash: (await scrypt(pw, salt)).toString('hex') }); }
      catch (e) { if (/23505/.test(e.body || '')) return bad(res, 'That email already has an account'); throw e; }
      await startSession(req, res, id); return send(res, 200, { user: { id, name } });
    }
    const salt = Buffer.from(found ? found.salt : '00'.repeat(16), 'hex'), h = await scrypt(pw, salt);
    if (!found || !crypto.timingSafeEqual(h, Buffer.from(found.hash, 'hex'))) return bad(res, 'Email or password doesn’t match', 401);
    await startSession(req, res, found.id); return send(res, 200, { user: { id: found.id, name: found.name } });
  }
  if (m === 'POST' && r0 === 'logout') {
    const t = cookie(req, 'pp_sid'); if (t) await rest('DELETE', `sessions?token_hash=eq.${sha(t)}`).catch(() => {});
    res.setHeader('Set-Cookie', 'pp_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); return send(res, 200, { ok: true });
  }
  if (m === 'GET' && r0 === 'me') return send(res, 200, { user: u ? { id: u.id, name: u.name } : null, favs: u ? u.favs : [] });

  if (r0 === 'pets') {
    if (m === 'GET' && parts.length === 1) {
      const rows = await rest('GET', 'pets?select=id,uid,n,c,g,t,p,a,w,l,d,img,at,users(name)&order=at.desc&limit=500');
      return send(res, 200, { pets: rows.map(x => pub(x, u)) });
    }
    if (m === 'POST' && parts.length === 1) {
      if (need()) return; if (limited('p' + u.id, 20, 36e5)) return bad(res, 'You’re posting a lot – please wait a bit', 429);
      const n = S(b.name, 40), l = S(b.location, 60); if (!n || !l) return bad(res, 'Name and location please');
      const c = CATS.includes(b.cat) ? b.cat : 'other', t = b.type === 'sell' ? 'sell' : 'adopt';
      let img = null; if (b.image) { img = await saveImg(b.image); if (!img) return bad(res, 'That photo couldn’t be used'); }
      const row = { id: rid(), uid: u.id, n, c, g: b.gender === 'f' ? 'f' : 'm', t, p: t === 'sell' ? S(b.price, 20) : '', a: S(b.age, 30), w: S(b.weight, 20), l, d: S(b.desc, 600), img };
      await rest('POST', 'pets', row);
      return send(res, 200, { pet: pub({ ...row, at: new Date().toISOString(), users: { name: u.name } }, u) });
    }
    const pet = (await rest('GET', `pets?id=eq.${q(parts[1] || '')}&select=id,uid,n,img`))[0]; if (!pet) return bad(res, 'Pet not found', 404);
    if (m === 'DELETE' && parts.length === 2) {
      if (need()) return; if (pet.uid !== u.id) return bad(res, 'Not your pet', 403);
      await rest('DELETE', `pets?id=eq.${q(pet.id)}`); delImg(pet.img); return send(res, 200, { ok: true });
    }
    if (m === 'POST' && parts[2] === 'messages') {
      if (need()) return; if (pet.uid === u.id) return bad(res, 'That’s your own pet');
      if (limited('m' + u.id, 20, 36e5)) return bad(res, 'Too many messages – try again later', 429);
      const text = S(b.text, 500); if (!text) return bad(res, 'Write a short message first');
      await rest('POST', 'messages', { id: rid(), pid: pet.id, from_uid: u.id, text }); return send(res, 200, { ok: true });
    }
  }
  if (m === 'POST' && r0 === 'favs' && parts[1]) {
    if (need()) return; const favs = (u.favs || []).slice(), i = favs.indexOf(parts[1]);
    if (i >= 0) favs.splice(i, 1);
    else if (favs.length < 200 && (await rest('GET', `pets?id=eq.${q(parts[1])}&select=id`)).length) favs.push(parts[1]);
    await rest('PATCH', `users?id=eq.${q(u.id)}`, { favs }); return send(res, 200, { favs });
  }
  if (m === 'GET' && r0 === 'inbox') {
    if (need()) return;
    const rows = await rest('GET', `messages?select=id,text,at,pets!inner(n,uid),users(name,email)&pets.uid=eq.${q(u.id)}&order=at.desc&limit=200`);
    return send(res, 200, { messages: rows.map(x => ({ id: x.id, pet: x.pets.n, from: (x.users || {}).name || 'Someone', email: (x.users || {}).email || '', text: x.text, at: x.at })) });
  }
  if (r0 === 'posts') {
    if (m === 'GET') { const rows = await rest('GET', 'posts?select=c,x,at,users(name)&order=at.desc&limit=200'); return send(res, 200, { posts: rows.map(x => ({ c: x.c, u: (x.users || {}).name || 'Someone', x: x.x, at: x.at })) }); }
    if (m === 'POST') {
      if (need()) return; if (limited('c' + u.id, 30, 36e5)) return bad(res, 'Slow down a little 🐾', 429);
      const x = S(b.text, 300); if (!x) return bad(res, 'Write something first');
      await rest('POST', 'posts', { id: rid(), uid: u.id, c: CATS.includes(b.c) ? b.c : 'other', x }); return send(res, 200, { ok: true });
    }
  }
  return bad(res, 'Not found', 404);
}

// ---------- static files ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serve(res, rel) {
  if (rel.endsWith('/')) rel += 'index.html';
  let f = path.normalize(path.join(PUB, rel));
  if (!f.startsWith(PUB + path.sep)) return bad(res, 'Not found', 404);
  fs.stat(f, (e, st) => {
    if (e || !st.isFile()) { if (path.extname(rel)) return bad(res, 'Not found', 404); f = path.join(PUB, 'index.html'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    fs.createReadStream(f).pipe(res);
  });
}
http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: ${SB}; connect-src 'self'; frame-ancestors 'none'`);
  if (secure(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p === '/health') { let db = false; try { await rest('GET', 'users?select=id&limit=1'); db = true; } catch (e) { console.error('health:', e.message); } return send(res, 200, { ok: true, db }); }
    if (p.startsWith('/api/')) return await api(req, res, p.slice(4));
    return serve(res, p);
  } catch (e) { console.error(e.message); if (!res.headersSent) bad(res, 'Something went wrong on our side – please try again', 500); }
}).listen(PORT, () => { console.log('🐾 Pawfect Homes running on port ' + PORT); rest('DELETE', `sessions?exp=lt.${q(new Date().toISOString())}`).catch(() => {}); });
