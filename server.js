'use strict';
// Pawfect Homes – zero-dependency Node server (built by Nemath & Tanaaz)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public'), UP = path.join(DATA, 'uploads'), DBF = path.join(DATA, 'db.json');
fs.mkdirSync(UP, { recursive: true });

// ---------- tiny JSON database ----------
let db = { users: [], pets: [], posts: [], messages: [], sessions: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DBF, 'utf8'))); } catch (e) {}
for (const k of Object.keys(db.sessions)) if (db.sessions[k].exp < Date.now()) delete db.sessions[k];
let timer = null;
const flush = () => { try { fs.writeFileSync(DBF + '.tmp', JSON.stringify(db)); fs.renameSync(DBF + '.tmp', DBF); } catch (e) { console.error('save failed', e.message); } };
const save = () => { clearTimeout(timer); timer = setTimeout(flush, 300); };
['SIGTERM', 'SIGINT'].forEach(s => process.on(s, () => { flush(); process.exit(0); }));

// ---------- helpers ----------
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
function startSession(req, res, uid) {
  const tok = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(tok)] = { uid, exp: Date.now() + 30 * 864e5 }; save();
  res.setHeader('Set-Cookie', `pp_sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${secure(req) ? '; Secure' : ''}`);
}
function userOf(req) {
  const t = cookie(req, 'pp_sid'); if (!t) return null;
  const s = db.sessions[sha(t)]; if (!s || s.exp < Date.now()) return null;
  return db.users.find(u => u.id === s.uid) || null;
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
function saveImg(s) {
  if (typeof s !== 'string' || s.length > 700000) return null;
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(s); if (!m) return null;
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length > 500e3 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  const id = rid() + '.jpg'; fs.writeFileSync(path.join(UP, id), buf); return '/uploads/' + id;
}
const CATS = ['cat', 'dog', 'rabbit', 'bird', 'other'];
const ownerName = id => (db.users.find(x => x.id === id) || {}).name || 'Someone';
const pub = (p, u) => ({ id: p.id, n: p.n, c: p.c, g: p.g, t: p.t, p: p.p, a: p.a, w: p.w, l: p.l, d: p.d, img: p.img, by: ownerName(p.uid), dt: p.at, mine: !!u && u.id === p.uid });

// ---------- API ----------
async function api(req, res, p) {
  const m = req.method, u = userOf(req), ip = ipOf(req), parts = p.split('/').filter(Boolean);
  if (m !== 'GET') {
    if (!(req.headers['content-type'] || '').includes('application/json')) return bad(res, 'Bad request');
    const o = req.headers.origin; if (o) { try { if (new URL(o).host !== req.headers.host) return bad(res, 'Bad origin', 403); } catch (e) { return bad(res, 'Bad origin', 403); } }
  }
  let b = {}; if (m === 'POST') { try { b = await readBody(req); } catch (e) { return bad(res, e.message, 413); } }
  const need = () => { if (!u) { bad(res, 'Please sign in first', 401); return true; } };
  const r0 = parts[0];

  if (m === 'POST' && (r0 === 'signup' || r0 === 'login')) {
    if (limited('a' + ip, 15, 9e5)) return bad(res, 'Too many attempts – try again in a few minutes', 429);
    const email = S(b.email, 120).toLowerCase(), pw = typeof b.password === 'string' ? b.password : '';
    if (!/^\S+@\S+\.\S+$/.test(email) || pw.length < 8 || pw.length > 200) return bad(res, 'Enter a valid email and a password of 8+ characters');
    if (r0 === 'signup') {
      const name = S(b.name, 30); if (!name) return bad(res, 'Please add your name');
      if (db.users.find(x => x.email === email)) return bad(res, 'That email already has an account');
      const salt = crypto.randomBytes(16);
      const user = { id: rid(), name, email, salt: salt.toString('hex'), hash: (await scrypt(pw, salt)).toString('hex'), favs: [], at: new Date().toISOString() };
      db.users.push(user); startSession(req, res, user.id); return send(res, 200, { user: { id: user.id, name } });
    }
    const user = db.users.find(x => x.email === email);
    const salt = Buffer.from(user ? user.salt : '00'.repeat(16), 'hex'), h = await scrypt(pw, salt);
    if (!user || !crypto.timingSafeEqual(h, Buffer.from(user.hash, 'hex'))) return bad(res, 'Email or password doesn’t match', 401);
    startSession(req, res, user.id); return send(res, 200, { user: { id: user.id, name: user.name } });
  }
  if (m === 'POST' && r0 === 'logout') {
    const t = cookie(req, 'pp_sid'); if (t) { delete db.sessions[sha(t)]; save(); }
    res.setHeader('Set-Cookie', 'pp_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); return send(res, 200, { ok: true });
  }
  if (m === 'GET' && r0 === 'me') return send(res, 200, { user: u ? { id: u.id, name: u.name } : null, favs: u ? u.favs : [] });

  if (r0 === 'pets') {
    if (m === 'GET' && parts.length === 1) return send(res, 200, { pets: db.pets.slice().reverse().map(x => pub(x, u)) });
    if (m === 'POST' && parts.length === 1) {
      if (need()) return; if (limited('p' + u.id, 20, 36e5)) return bad(res, 'You’re posting a lot – please wait a bit', 429);
      const n = S(b.name, 40), l = S(b.location, 60); if (!n || !l) return bad(res, 'Name and location please');
      const c = CATS.includes(b.cat) ? b.cat : 'other', t = b.type === 'sell' ? 'sell' : 'adopt';
      let img = null; if (b.image) { img = saveImg(b.image); if (!img) return bad(res, 'That photo couldn’t be used'); }
      const pet = { id: rid(), uid: u.id, n, c, g: b.gender === 'f' ? 'f' : 'm', t, p: t === 'sell' ? S(b.price, 20) : '', a: S(b.age, 30), w: S(b.weight, 20), l, d: S(b.desc, 600), img, at: new Date().toISOString() };
      db.pets.push(pet); save(); return send(res, 200, { pet: pub(pet, u) });
    }
    const pet = db.pets.find(x => x.id === parts[1]); if (!pet) return bad(res, 'Pet not found', 404);
    if (m === 'DELETE' && parts.length === 2) {
      if (need()) return; if (pet.uid !== u.id) return bad(res, 'Not your pet', 403);
      if (pet.img) fs.unlink(path.join(UP, path.basename(pet.img)), () => {});
      db.pets = db.pets.filter(x => x !== pet); db.messages = db.messages.filter(x => x.pid !== pet.id); save(); return send(res, 200, { ok: true });
    }
    if (m === 'POST' && parts[2] === 'messages') {
      if (need()) return; if (pet.uid === u.id) return bad(res, 'That’s your own pet');
      if (limited('m' + u.id, 20, 36e5)) return bad(res, 'Too many messages – try again later', 429);
      const text = S(b.text, 500); if (!text) return bad(res, 'Write a short message first');
      db.messages.push({ id: rid(), pid: pet.id, from: u.id, text, at: new Date().toISOString() }); save(); return send(res, 200, { ok: true });
    }
  }
  if (m === 'POST' && r0 === 'favs' && parts[1]) {
    if (need()) return; const i = u.favs.indexOf(parts[1]);
    if (i >= 0) u.favs.splice(i, 1); else if (db.pets.some(x => x.id === parts[1]) && u.favs.length < 200) u.favs.push(parts[1]);
    save(); return send(res, 200, { favs: u.favs });
  }
  if (m === 'GET' && r0 === 'inbox') {
    if (need()) return; const mine = new Map(db.pets.filter(x => x.uid === u.id).map(x => [x.id, x]));
    return send(res, 200, { messages: db.messages.filter(x => mine.has(x.pid)).reverse().map(x => { const f = db.users.find(y => y.id === x.from) || {}; return { id: x.id, pet: mine.get(x.pid).n, from: f.name || 'Someone', email: f.email || '', text: x.text, at: x.at }; }) });
  }
  if (r0 === 'posts') {
    if (m === 'GET') return send(res, 200, { posts: db.posts.slice(-200).reverse().map(x => ({ c: x.c, u: ownerName(x.uid), x: x.x, at: x.at })) });
    if (m === 'POST') {
      if (need()) return; if (limited('c' + u.id, 30, 36e5)) return bad(res, 'Slow down a little 🐾', 429);
      const x = S(b.text, 300); if (!x) return bad(res, 'Write something first');
      db.posts.push({ id: rid(), uid: u.id, c: CATS.includes(b.c) ? b.c : 'other', x, at: new Date().toISOString() }); save(); return send(res, 200, { ok: true });
    }
  }
  return bad(res, 'Not found', 404);
}

// ---------- static files ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serve(res, dir, rel, cache) {
  if (rel.endsWith('/')) rel += 'index.html';
  let f = path.normalize(path.join(dir, rel));
  if (!f.startsWith(dir + path.sep)) return bad(res, 'Not found', 404);
  fs.stat(f, (e, st) => {
    if (e || !st.isFile()) { if (path.extname(rel) || dir !== PUB) return bad(res, 'Not found', 404); f = path.join(PUB, 'index.html'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': cache ? 'public, max-age=86400' : 'no-cache' });
    fs.createReadStream(f).pipe(res);
  });
}

http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'");
  if (secure(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p === '/health') return send(res, 200, { ok: true });
    if (p.startsWith('/api/')) return await api(req, res, p.slice(4));
    if (p.startsWith('/uploads/')) return /^[a-f0-9]+\.jpg$/.test(p.slice(9)) ? serve(res, UP, p.slice(9), true) : bad(res, 'Not found', 404);
    return serve(res, PUB, p);
  } catch (e) { console.error(e); if (!res.headersSent) bad(res, 'Server error', 500); }
}).listen(PORT, () => console.log('🐾 Pawfect Homes running on port ' + PORT));
