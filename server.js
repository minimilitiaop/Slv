'use strict';
/**
 * Selov asx — storefront + payments + admin server.
 * Zero dependencies. Requires Node 18+.
 *
 * Security model:
 *  - Balance can ONLY change through admin-authenticated endpoints (payment approval / manual adjust)
 *    or through a server-validated order purchase. The browser is never trusted.
 *  - Admin dashboard HTML/JS are only served after a valid admin session cookie.
 *  - Admin password is scrypt-hashed; login is rate-limited with lockout.
 */
// ---- friendly startup checks ------------------------------------------------
if (Number(process.versions.node.split('.')[0]) < 18) {
  console.error('\nSelov asx needs Node.js 18 or newer. You have ' + process.version + '.\nInstall the LTS version from https://nodejs.org and run again.\n');
  process.exit(1);
}
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Optional .env file (KEY=value per line) next to server.js. Real environment variables always win.
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i.exec(line);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
} catch { /* no .env file - that's fine */ }

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const ADMIN_DIR = path.join(ROOT, 'adminsecretwow');
const DATA = path.join(ROOT, 'data');
const UPLOADS = path.join(DATA, 'uploads');
const DB_FILE = path.join(DATA, 'db.json');
const SECURE_COOKIE = process.env.COOKIE_SECURE === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
let ADMIN_PATH = (process.env.ADMIN_PATH || '/adminsecretwow').replace(/\/+$/, '');
if (!/^\/[A-Za-z0-9_\-]+$/.test(ADMIN_PATH)) ADMIN_PATH = '/adminsecretwow';

try { fs.mkdirSync(UPLOADS, { recursive: true }); fs.accessSync(DATA, fs.constants.W_OK); } catch (e) {
  console.error('\nCannot write to the data folder (' + DATA + '): ' + e.code + '\n' +
    'This app saves its database and screenshots to disk, so it must run on a normal Node server/VPS\n' +
    '(not a read-only or serverless host such as Vercel/Netlify/GitHub Pages).\n');
  process.exit(1);
}

/* ------------------------------------------------------------------ DB */
const DEFAULT_SETTINGS = () => ({
  freeShares: 25,
  maxFreePerIp: 3,
  maxShares: 100000,
  minTopup: 20,
  maxTopup: 50000,
  tiers: [
    { name: 'Pro', minShares: 100, price: 0.5 },
    { name: 'Premium', minShares: 1000, price: 0.35 },
  ],
  gcash: { name: 'JU***Y B.', mobile: '+63 991 774 ••••', note: 'InstaPay QR · scan with GCash or any bank / e-wallet' },
  qrVersion: 1,
});

function freshDb() {
  return {
    v: 1, users: {}, byName: {}, sessions: {}, orders: [], payments: [], ledger: [], feedback: [],
    chats: {}, devices: {}, fps: {}, ipFree: {}, imgHashes: {}, refs: {}, admin: null, settings: DEFAULT_SETTINGS(),
    portfolio: null,
  };
}

function DEFAULT_PORTFOLIO() {
  return [
    { id: 'p1', title: 'MultiSave', link: 'https://multisave.freedev.app', badge: 'Downloader', tone: 'ok', price: 'Free',
      desc: 'Download YouTube videos as MP4 or audio as MP3, plus media from TikTok, Facebook, Instagram, X, Pinterest, Snapchat, CapCut, Threads, Likee and Spotify.',
      image: '/assets/portfolio-multisave.webp', visible: true },
    { id: 'p2', title: 'JaySoundCloud', link: 'https://jaysoundcloud.onrender.com', badge: 'Music app', tone: 'warn', price: 'Free',
      desc: 'Discover OPM through live radio, music recommendations and playlists in a simple web app.',
      image: '/assets/portfolio-jaysoundcloud.webp', visible: true },
    { id: 'p3', title: 'Stranger Cam', link: 'https://strangercamm.onrender.com/', badge: 'Video chat', tone: 'ok', price: 'Free',
      desc: 'Meet new people through random video chat, or switch to text chat from your browser.',
      image: '/assets/portfolio-strangercam.webp', visible: true },
  ];
}

let db;
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { db = freshDb(); }
{
  const f = freshDb();
  for (const k of Object.keys(f)) if (db[k] === undefined) db[k] = f[k];
  db.settings = Object.assign(DEFAULT_SETTINGS(), db.settings);
  if (!Array.isArray(db.portfolio)) db.portfolio = DEFAULT_PORTFOLIO();
}

let saveTimer = null;
function saveNow() {
  clearTimeout(saveTimer); saveTimer = null;
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
function save() { if (!saveTimer) saveTimer = setTimeout(saveNow, 150); }
process.on('SIGINT', () => { saveNow(); process.exit(0); });
process.on('SIGTERM', () => { saveNow(); process.exit(0); });

/* ------------------------------------------------------------ crypto */
function hashSecret(secret) {
  const s = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(secret), s, 64);
  return { s: s.toString('hex'), h: h.toString('hex') };
}
function verifySecret(secret, rec) {
  if (!rec) return false;
  try {
    const h = crypto.scryptSync(String(secret), Buffer.from(rec.s, 'hex'), 64);
    return crypto.timingSafeEqual(h, Buffer.from(rec.h, 'hex'));
  } catch { return false; }
}
const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
/** Unique, never-repeating id. Re-rolls on the (unlikely) collision. */
function uid(prefix, exists, len = 6) {
  for (;;) {
    const b = crypto.randomBytes(len);
    let s = '';
    for (let i = 0; i < len; i++) s += ALPHA[b[i] % ALPHA.length];
    const id = `${prefix}-${s}`;
    if (!exists(id)) return id;
  }
}
const now = () => Date.now();

/* ------------------------------------------------------ admin account */
const envAdminPassword = process.env.ADMIN_PASSWORD;
if (envAdminPassword && envAdminPassword.length < 10) {
  console.error('ADMIN_PASSWORD must be at least 10 characters.');
  process.exit(1);
}
if (envAdminPassword) {
  // An explicitly configured environment value is the source of truth on every start.
  if (!db.admin || !verifySecret(envAdminPassword, db.admin)) {
    db.admin = hashSecret(envAdminPassword);
    saveNow();
  }
  console.log(`Admin password loaded from ADMIN_PASSWORD for ${ADMIN_PATH}.`);
} else if (!db.admin) {
  const pw = crypto.randomBytes(10).toString('base64url');
  db.admin = hashSecret(pw);
  saveNow();
  console.log('\n==============================================================');
  console.log(' Selov asx admin account created');
  console.log(` Admin URL     : http://localhost:${PORT}${ADMIN_PATH}`);
  console.log(` Admin password: ${pw}    <-- save this now, it is shown once`);
  console.log('==============================================================\n');
}

/* ----------------------------------------------------------- helpers */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
};
function secHeaders(res, nonce) {
  res.setHeader('Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; ` +
    "img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
}
function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg) => new HttpError(400, msg);

function parseCookies(req) {
  const out = {};
  for (const p of (req.headers.cookie || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
function setCookie(res, name, value, { maxAge, sameSite = 'Lax' } = {}) {
  let c = `${name}=${value}; Path=/; HttpOnly; SameSite=${sameSite}`;
  if (maxAge !== undefined) c += `; Max-Age=${maxAge}`;
  if (SECURE_COOKIE) c += '; Secure';
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, c) : c);
}
function clientIp(req) {
  if (TRUST_PROXY) {
    const x = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (x) return x;
  }
  return (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let n = 0, over = false;
    const chunks = [];
    req.on('data', (c) => { n += c.length; if (n > limit) over = true; else chunks.push(c); });
    req.on('end', () => over ? reject(new HttpError(413, 'File or request too large')) : resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/* ------------------------------------------------------- rate limits */
const buckets = new Map();
function limited(key, max, windowMs) {
  const t = now();
  let b = buckets.get(key);
  if (!b || b.reset < t) { b = { n: 0, reset: t + windowMs }; buckets.set(key, b); }
  b.n++;
  return b.n > max;
}
setInterval(() => { const t = now(); for (const [k, b] of buckets) if (b.reset < t) buckets.delete(k); }, 60000).unref();

/* ---------------------------------------------------------- sessions */
const adminSessions = new Map(); // hash -> {exp, ua}
function getUserFromReq(req) {
  const tok = parseCookies(req).sv_u;
  if (!tok || tok.length < 20) return null;
  const s = db.sessions[sha(tok)];
  if (!s) return null;
  if (s.exp < now()) { delete db.sessions[sha(tok)]; return null; }
  const u = db.users[s.uid];
  return u && !u.banned ? u : null;
}
function isAdmin(req) {
  const tok = parseCookies(req).sv_a;
  if (!tok) return false;
  const h = sha(tok);
  const s = adminSessions.get(h);
  if (!s) return false;
  if (s.exp < now()) { adminSessions.delete(h); return false; }
  return s.ua === sha(String(req.headers['user-agent'] || ''));
}

/* --------------------------------------------------------------- SSE */
const adminClients = new Set();
const userClients = new Map();
function openSse(req, res, onClose) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.write('retry: 3000\n\n');
  req.on('close', onClose);
}
const sseMsg = (type, data) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
function pushAdmin(type, data) { for (const r of adminClients) r.write(sseMsg(type, data)); }
function pushUser(uid_, type, data) { const s = userClients.get(uid_); if (s) for (const r of s) r.write(sseMsg(type, data)); }
setInterval(() => {
  for (const r of adminClients) r.write(': ping\n\n');
  for (const s of userClients.values()) for (const r of s) r.write(': ping\n\n');
}, 25000).unref();

/* ----------------------------------------------------------- domain */
const cents = (v) => { const n = Number(v); if (!Number.isFinite(n)) throw bad('Invalid amount'); return Math.round(n * 100); };
const pesos = (c) => c / 100;
function pubUser(u) { return { id: u.id, username: u.username, balance: pesos(u.balance), createdAt: u.createdAt }; }
function freeAvailable(u, deviceId, fp, ip) {
  if (u.freeUsed) return false;
  if (db.devices[deviceId]) return false;
  if (fp && db.fps[fp]) return false;
  if ((db.ipFree[ip] || 0) >= db.settings.maxFreePerIp) return false;
  return true;
}
function ledger(u, delta, reason, by) {
  db.ledger.push({ id: db.ledger.length + 1, userId: u.id, delta, reason, by, ts: now(), balanceAfter: u.balance });
  if (db.ledger.length > 20000) db.ledger.splice(0, 2000);
}
function tierFor(shares) {
  const tiers = [...db.settings.tiers].sort((a, b) => a.minShares - b.minShares);
  let t = null;
  for (const x of tiers) if (shares >= x.minShares) t = x;
  return t;
}
function priceFor(shares) {
  const t = tierFor(shares);
  if (!t) {
    const min = Math.min(...db.settings.tiers.map((x) => x.minShares));
    throw bad(`Minimum paid order is ${min} shares`);
  }
  return { tier: t, cost: Math.max(1, Math.round(shares * t.price * 100)) };
}
function validFbUrl(raw) {
  let u;
  try { u = new URL(String(raw).trim()); } catch { throw bad('Enter a valid Facebook link'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw bad('Enter a valid Facebook link');
  if (!/(^|\.)(facebook\.com|fb\.com|fb\.watch|fb\.me)$/i.test(u.hostname)) throw bad('Link must be a facebook.com post URL');
  if (u.href.length > 500) throw bad('Link is too long');
  return u.href;
}
function sniffImage(buf) {
  if (buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}
function decodeImage(dataUrl, maxBytes) {
  if (typeof dataUrl !== 'string') throw bad('Image required');
  const i = dataUrl.indexOf(';base64,');
  if (!dataUrl.startsWith('data:image/') || i < 0) throw bad('Upload a JPG, PNG or WEBP image');
  const buf = Buffer.from(dataUrl.slice(i + 8), 'base64');
  if (buf.length > maxBytes) throw new HttpError(413, 'Image too large (max ' + Math.round(maxBytes / 1048576) + 'MB)');
  const ext = sniffImage(buf);
  if (!ext) throw bad('Upload a JPG, PNG or WEBP image');
  return { buf, ext };
}
const str = (v, max, min = 0) => {
  if (typeof v !== 'string') throw bad('Invalid input');
  const s = v.trim();
  if (s.length < min || s.length > max) throw bad(min ? `Must be ${min}-${max} characters` : `Max ${max} characters`);
  return s;
};
function thread(uid_) {
  return db.chats[uid_] || (db.chats[uid_] = { msgs: [], unreadAdmin: 0, unreadUser: 0, last: 0 });
}
const loginFails = new Map(); // key -> {n, lock}

/* ------------------------------------------------------------ routes */
const routes = [];
function route(method, pattern, opts, fn) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-z]+)/gi, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, opts, fn });
}

/* ---- public config ---- */
route('GET', '/api/config', {}, (c) => {
  const s = db.settings;
  const done = db.orders.filter((o) => o.status === 'completed');
  json(c.res, 200, {
    freeShares: s.freeShares, maxShares: s.maxShares, minTopup: s.minTopup, maxTopup: s.maxTopup,
    tiers: [...s.tiers].sort((a, b) => a.minShares - b.minShares),
    gcash: s.gcash, qr: '/qr?v=' + s.qrVersion,
    stats: { users: Object.keys(db.users).length, orders: done.length, shares: done.reduce((a, o) => a + o.shares, 0) },
  });
});

/* ---- portfolio (public read, admin edit) */
const pubProject = (p) => ({ id: p.id, title: p.title, link: p.link, badge: p.badge, tone: p.tone, price: p.price, desc: p.desc, image: p.image });
route('GET', '/api/portfolio', {}, (c) => {
  json(c.res, 200, db.portfolio.filter((p) => p.visible).map(pubProject));
});
route('GET', '/api/admin/portfolio', { admin: true }, (c) => { json(c.res, 200, db.portfolio); });
route('POST', '/api/admin/portfolio', { admin: true, maxBody: 262144 }, (c) => {
  const list = c.body.items;
  if (!Array.isArray(list) || list.length > 24) throw bad('Invalid project list (max 24)');
  const old = new Map(db.portfolio.map((p) => [p.id, p]));
  const out = [];
  const ids = new Set();
  for (const it of list) {
    const title = str(it.title, 60, 1);
    const link = String(it.link || '').trim();
    let u; try { u = new URL(link); } catch { throw bad('Link must be a full URL like https://example.com'); }
    if (!/^https?:$/.test(u.protocol) || link.length > 300) throw bad('Link must start with http:// or https://');
    let id = /^[a-z0-9]{2,16}$/.test(String(it.id || '')) ? it.id : 'p' + crypto.randomBytes(4).toString('hex');
    if (ids.has(id)) id = 'p' + crypto.randomBytes(4).toString('hex');
    ids.add(id);
    const prev = old.get(id);
    let image = prev ? prev.image : '';
    if (it.image === '') image = '';
    out.push({
      id, title, link: u.href,
      badge: String(it.badge || '').trim().slice(0, 24),
      tone: it.tone === 'warn' ? 'warn' : 'ok',
      price: String(it.price || '').trim().slice(0, 40),
      desc: String(it.desc || '').trim().slice(0, 300),
      image, visible: it.visible !== false,
    });
  }
  for (const p of db.portfolio) {
    if (!ids.has(p.id) || (out.find((o) => o.id === p.id).image === '' && p.image)) removePfFile(p.image);
  }
  db.portfolio = out;
  save();
  json(c.res, 200, db.portfolio);
});
route('POST', '/api/admin/portfolio/image', { admin: true, maxBody: 9 * 1048576 }, (c) => {
  const p = db.portfolio.find((x) => x.id === String(c.body.id || ''));
  if (!p) throw new HttpError(404, 'Save the project first, then upload its image');
  const { buf, ext } = decodeImage(c.body.image, 6 * 1048576);
  const name = 'pf-' + p.id + '-' + crypto.randomBytes(3).toString('hex') + '.' + ext;
  fs.writeFileSync(path.join(UPLOADS, name), buf);
  removePfFile(p.image);
  p.image = '/media/' + name;
  save();
  json(c.res, 200, { image: p.image });
});
function removePfFile(img) {
  const m = /^\/media\/(pf-[a-z0-9-]+\.(?:jpg|png|webp))$/.exec(img || '');
  if (m) { try { fs.unlinkSync(path.join(UPLOADS, m[1])); } catch { /* gone */ } }
}
route('GET', '/api/testimonials', {}, (c) => {
  json(c.res, 200, db.feedback.filter((f) => f.public).slice(-12).reverse().map((f) => ({ name: f.name, rating: f.rating, message: f.message })));
});

/* ---- accounts ---- */
route('POST', '/api/register', { rl: ['reg', 6, 3600000] }, (c) => {
  const username = str(c.body.username, 20, 3);
  if (!/^[A-Za-z0-9_.]+$/.test(username)) throw bad('Username: letters, numbers, _ and . only');
  const pin = String(c.body.pin || '');
  if (!/^\d{4,8}$/.test(pin)) throw bad('PIN must be 4-8 digits');
  const key = username.toLowerCase();
  if (db.byName[key]) throw bad('That username is taken');
  const id = uid('SLV', (x) => !!db.users[x]);
  db.users[id] = { id, username, pin: hashSecret(pin), balance: 0, createdAt: now(), freeUsed: false, banned: false };
  db.byName[key] = id;
  startSession(c, id);
  save();
  pushAdmin('user', { id, username });
  json(c.res, 200, { user: pubUser(db.users[id]) });
});
function startSession(c, userId) {
  const tok = crypto.randomBytes(32).toString('base64url');
  db.sessions[sha(tok)] = { uid: userId, exp: now() + 30 * 86400000 };
  setCookie(c.res, 'sv_u', tok, { maxAge: 30 * 86400 });
}
route('POST', '/api/login', { rl: ['login', 20, 600000] }, (c) => {
  const who = str(c.body.id, 40, 3);
  const pin = String(c.body.pin || '');
  const u = db.users[who.toUpperCase()] || db.users[db.byName[who.toLowerCase()]];
  const fkey = 'u:' + (u ? u.id : who.toLowerCase());
  const f = loginFails.get(fkey);
  if (f && f.lock > now()) throw new HttpError(429, 'Too many attempts. Try again in a few minutes.');
  if (!u || !verifySecret(pin, u.pin)) {
    const x = f || { n: 0, lock: 0 };
    x.n++; if (x.n >= 8) { x.lock = now() + 900000; x.n = 0; }
    loginFails.set(fkey, x);
    throw new HttpError(401, 'Wrong ID/username or PIN');
  }
  if (u.banned) throw new HttpError(403, 'This account is disabled');
  loginFails.delete(fkey);
  startSession(c, u.id);
  json(c.res, 200, { user: pubUser(u) });
});
route('POST', '/api/logout', {}, (c) => {
  const tok = parseCookies(c.req).sv_u;
  if (tok) { delete db.sessions[sha(tok)]; save(); }
  setCookie(c.res, 'sv_u', '', { maxAge: 0 });
  json(c.res, 200, { ok: true });
});
route('GET', '/api/me', {}, (c) => {
  const u = getUserFromReq(c.req);
  if (!u) return json(c.res, 200, { user: null });
  const fp = String(c.query.get('fp') || '');
  json(c.res, 200, {
    user: pubUser(u),
    freeAvailable: freeAvailable(u, c.deviceId, /^[a-f0-9]{16,64}$/.test(fp) ? fp : '', c.ip),
    orders: db.orders.filter((o) => o.userId === u.id).slice(-30).reverse().map(pubOrder),
    payments: db.payments.filter((p) => p.userId === u.id).slice(-30).reverse().map(pubPayment),
    chatUnread: thread(u.id).unreadUser,
  });
});
const pubOrder = (o) => ({ id: o.id, url: o.url, shares: o.shares, cost: pesos(o.cost), free: o.free, status: o.status, createdAt: o.createdAt });
const pubPayment = (p) => ({ id: p.id, amount: pesos(p.amount), credited: pesos(p.credited || 0), ref: p.ref, status: p.status, note: p.note || '', createdAt: p.createdAt });

/* ---- orders ---- */
route('POST', '/api/orders', { auth: 'user', rl: ['order', 20, 600000] }, (c) => {
  const u = c.user;
  const url = validFbUrl(c.body.url);
  const shares = Math.floor(Number(c.body.shares));
  if (!Number.isFinite(shares) || shares < 1) throw bad('Enter how many shares you want');
  if (shares > db.settings.maxShares) throw bad(`Max ${db.settings.maxShares} shares per order`);
  if (db.orders.filter((o) => o.userId === u.id && (o.status === 'pending' || o.status === 'processing')).length >= 10) {
    throw bad('You have too many open orders. Wait for some to finish.');
  }
  const fp = /^[a-f0-9]{16,64}$/.test(String(c.body.fp || '')) ? String(c.body.fp) : '';
  let cost = 0, free = false;
  if (c.body.useFree) {
    if (!freeAvailable(u, c.deviceId, fp, c.ip)) throw bad('Your free share was already claimed on this device');
    if (shares > db.settings.freeShares) throw bad(`Free claim is up to ${db.settings.freeShares} shares`);
    free = true;
    u.freeUsed = true;
    db.devices[c.deviceId] = { uid: u.id, ts: now() };
    if (fp) db.fps[fp] = { uid: u.id, ts: now() };
    db.ipFree[c.ip] = (db.ipFree[c.ip] || 0) + 1;
  } else {
    cost = priceFor(shares).cost;
    if (u.balance < cost) throw new HttpError(402, `Not enough balance. You need ₱${pesos(cost).toFixed(2)} — add balance first.`);
    u.balance -= cost;
    ledger(u, -cost, 'Order purchase', 'system');
  }
  const id = uid('ORD', (x) => db.orders.some((o) => o.id === x));
  const o = { id, userId: u.id, username: u.username, url, shares, cost, free, status: 'pending', createdAt: now(), updatedAt: now() };
  db.orders.push(o);
  save();
  pushAdmin('order', { id, username: u.username, shares, free });
  json(c.res, 200, { order: pubOrder(o), balance: pesos(u.balance) });
});

/* ---- payments (screenshot) ---- */
route('POST', '/api/payments', { auth: 'user', rl: ['pay', 10, 3600000], maxBody: 9 * 1048576 }, (c) => {
  const u = c.user;
  const amount = cents(c.body.amount);
  if (amount < db.settings.minTopup * 100 || amount > db.settings.maxTopup * 100) {
    throw bad(`Amount must be ₱${db.settings.minTopup} – ₱${db.settings.maxTopup}`);
  }
  let ref = '';
  if (c.body.ref) {
    ref = String(c.body.ref).replace(/\s+/g, '').slice(0, 30);
    if (!/^[A-Za-z0-9\-]{6,30}$/.test(ref)) throw bad('Reference number looks invalid');
    if (db.refs[ref.toUpperCase()]) throw bad('That reference number was already submitted');
  }
  if (db.payments.filter((p) => p.userId === u.id && p.status === 'pending').length >= 5) {
    throw bad('You already have 5 pending payments. Please wait for approval.');
  }
  const { buf, ext } = decodeImage(c.body.image, 6 * 1048576);
  const h = sha(buf.toString('latin1'));
  if (db.imgHashes[h]) throw bad('This screenshot was already submitted');
  const id = uid('PAY', (x) => db.payments.some((p) => p.id === x));
  fs.writeFileSync(path.join(UPLOADS, `${id}.${ext}`), buf);
  db.imgHashes[h] = id;
  if (ref) db.refs[ref.toUpperCase()] = id;
  const p = { id, userId: u.id, username: u.username, amount, ref, file: `${id}.${ext}`, status: 'pending', createdAt: now() };
  db.payments.push(p);
  save();
  pushAdmin('payment', { id, username: u.username, userId: u.id, amount: pesos(amount) });
  json(c.res, 200, { payment: pubPayment(p) });
});

/* ---- feedback ---- */
route('POST', '/api/feedback', { rl: ['fb', 8, 3600000] }, (c) => {
  const type = ['feedback', 'report', 'idea'].includes(c.body.type) ? c.body.type : 'feedback';
  const message = str(c.body.message, 1200, 5);
  const rating = Math.min(5, Math.max(0, Math.floor(Number(c.body.rating) || 0)));
  const u = getUserFromReq(c.req);
  let name = u ? u.username : String(c.body.name || '').trim().slice(0, 30);
  if (!name) name = 'Guest';
  const f = {
    id: uid('FB', (x) => db.feedback.some((q) => q.id === x)), userId: u ? u.id : null, name, type, rating, message,
    status: 'new', public: false, createdAt: now(),
  };
  db.feedback.push(f);
  save();
  pushAdmin('feedback', { id: f.id, name, type, rating, message: message.slice(0, 120) });
  json(c.res, 200, { ok: true });
});

/* ---- chat (user side) ---- */
route('GET', '/api/chat', { auth: 'user' }, (c) => {
  const t = thread(c.user.id);
  t.unreadUser = 0; save();
  json(c.res, 200, { messages: t.msgs.slice(-100) });
});
route('POST', '/api/chat', { auth: 'user', rl: ['chat', 25, 60000] }, (c) => {
  const text = str(c.body.text, 1000, 1);
  const t = thread(c.user.id);
  const m = { id: t.msgs.length + 1, from: 'user', text, ts: now() };
  t.msgs.push(m); if (t.msgs.length > 500) t.msgs.splice(0, 100);
  t.unreadAdmin++; t.last = m.ts;
  save();
  pushAdmin('chat', { userId: c.user.id, username: c.user.username, text: text.slice(0, 120) });
  json(c.res, 200, { message: m });
});
route('GET', '/api/events', { auth: 'user', sse: true }, (c) => {
  const id = c.user.id;
  if (!userClients.has(id)) userClients.set(id, new Set());
  userClients.get(id).add(c.res);
  openSse(c.req, c.res, () => { const s = userClients.get(id); if (s) { s.delete(c.res); if (!s.size) userClients.delete(id); } });
});

/* ------------------------------------------------------------- ADMIN */
route('POST', '/api/admin/login', { admin: 'public' }, async (c) => {
  const key = 'a:' + c.ip;
  const f = loginFails.get(key);
  if (f && f.lock > now()) throw new HttpError(429, 'Locked. Try again later.');
  const pw = String(c.body.password || '');
  if (!verifySecret(pw, db.admin)) {
    const x = f || { n: 0, lock: 0 };
    x.n++; if (x.n >= 5) { x.lock = now() + 900000; x.n = 0; }
    loginFails.set(key, x);
    await new Promise((r) => setTimeout(r, 600));
    throw new HttpError(401, 'Wrong password');
  }
  loginFails.delete(key);
  const tok = crypto.randomBytes(32).toString('base64url');
  adminSessions.set(sha(tok), { exp: now() + 12 * 3600000, ua: sha(String(c.req.headers['user-agent'] || '')) });
  setCookie(c.res, 'sv_a', tok, { maxAge: 12 * 3600, sameSite: 'Strict' });
  json(c.res, 200, { ok: true });
});
route('POST', '/api/admin/logout', { admin: true }, (c) => {
  const tok = parseCookies(c.req).sv_a;
  if (tok) adminSessions.delete(sha(tok));
  setCookie(c.res, 'sv_a', '', { maxAge: 0, sameSite: 'Strict' });
  json(c.res, 200, { ok: true });
});
function summary() {
  return {
    pendingPayments: db.payments.filter((p) => p.status === 'pending').length,
    newFeedback: db.feedback.filter((f) => f.status === 'new').length,
    unreadChats: Object.values(db.chats).reduce((a, t) => a + (t.unreadAdmin > 0 ? 1 : 0), 0),
    pendingOrders: db.orders.filter((o) => o.status === 'pending').length,
    users: Object.keys(db.users).length,
    revenue: pesos(db.payments.filter((p) => p.status === 'approved').reduce((a, p) => a + (p.credited || 0), 0)),
    completedOrders: db.orders.filter((o) => o.status === 'completed').length,
    totalBalance: pesos(Object.values(db.users).reduce((a, u) => a + u.balance, 0)),
  };
}
route('GET', '/api/admin/summary', { admin: true }, (c) => json(c.res, 200, summary()));
route('GET', '/api/admin/events', { admin: true, sse: true }, (c) => {
  adminClients.add(c.res);
  openSse(c.req, c.res, () => adminClients.delete(c.res));
  c.res.write(sseMsg('summary', summary()));
});

route('GET', '/api/admin/payments', { admin: true }, (c) => {
  const st = c.query.get('status');
  let l = db.payments;
  if (st && st !== 'all') l = l.filter((p) => p.status === st);
  json(c.res, 200, l.slice(-200).reverse().map((p) => ({ ...pubPayment(p), userId: p.userId, username: p.username })));
});
route('GET', '/api/admin/payments/:id/image', { admin: true }, (c) => {
  const p = db.payments.find((x) => x.id === c.params.id);
  if (!p) throw new HttpError(404, 'Not found');
  const file = path.join(UPLOADS, path.basename(p.file));
  const ext = path.extname(file).toLowerCase();
  res_file(c.res, file, MIME[ext] || 'application/octet-stream', { 'Cache-Control': 'private, max-age=600', 'Content-Security-Policy': 'sandbox' });
});
route('POST', '/api/admin/payments/:id/decide', { admin: true }, (c) => {
  const p = db.payments.find((x) => x.id === c.params.id);
  if (!p) throw new HttpError(404, 'Payment not found');
  if (p.status !== 'pending') throw bad('Already ' + p.status);
  const u = db.users[p.userId];
  if (c.body.approve) {
    const amt = c.body.amount !== undefined && c.body.amount !== '' ? cents(c.body.amount) : p.amount;
    if (amt <= 0 || amt > 100000000) throw bad('Invalid amount');
    p.status = 'approved'; p.credited = amt;
    u.balance += amt;
    ledger(u, amt, `Payment ${p.id} approved`, 'admin');
  } else {
    p.status = 'rejected'; p.note = String(c.body.note || '').slice(0, 200);
  }
  p.decidedAt = now();
  save();
  pushUser(u.id, 'payment', { id: p.id, status: p.status, balance: pesos(u.balance), credited: pesos(p.credited || 0), note: p.note || '' });
  json(c.res, 200, { ok: true, summary: summary() });
});

route('GET', '/api/admin/users', { admin: true }, (c) => {
  const q = String(c.query.get('q') || '').trim().toLowerCase();
  let l = Object.values(db.users);
  if (q) l = l.filter((u) => u.id.toLowerCase().includes(q) || u.username.toLowerCase().includes(q));
  l.sort((a, b) => b.createdAt - a.createdAt);
  json(c.res, 200, l.slice(0, 100).map((u) => ({ id: u.id, username: u.username, balance: pesos(u.balance), banned: u.banned, freeUsed: u.freeUsed, createdAt: u.createdAt, orders: db.orders.filter((o) => o.userId === u.id).length })));
});
route('GET', '/api/admin/users/:id', { admin: true }, (c) => {
  const u = db.users[String(c.params.id).toUpperCase()];
  if (!u) throw new HttpError(404, 'No user with that ID');
  json(c.res, 200, {
    id: u.id, username: u.username, balance: pesos(u.balance), banned: u.banned, freeUsed: u.freeUsed, createdAt: u.createdAt,
    ledger: db.ledger.filter((l) => l.userId === u.id).slice(-15).reverse().map((l) => ({ delta: pesos(l.delta), reason: l.reason, by: l.by, ts: l.ts })),
  });
});
route('POST', '/api/admin/users/:id/balance', { admin: true }, (c) => {
  const u = db.users[String(c.params.id).toUpperCase()];
  if (!u) throw new HttpError(404, 'No user with that ID');
  const delta = cents(c.body.amount);
  if (delta === 0 || Math.abs(delta) > 100000000) throw bad('Enter a non-zero amount');
  if (u.balance + delta < 0) throw bad('That would make the balance negative');
  u.balance += delta;
  ledger(u, delta, String(c.body.note || 'Manual adjustment').slice(0, 120), 'admin');
  save();
  pushUser(u.id, 'balance', { balance: pesos(u.balance), delta: pesos(delta) });
  json(c.res, 200, { id: u.id, balance: pesos(u.balance) });
});
route('POST', '/api/admin/users/:id/ban', { admin: true }, (c) => {
  const u = db.users[String(c.params.id).toUpperCase()];
  if (!u) throw new HttpError(404, 'No user with that ID');
  u.banned = !!c.body.banned;
  if (u.banned) for (const [h, s] of Object.entries(db.sessions)) if (s.uid === u.id) delete db.sessions[h];
  save();
  json(c.res, 200, { ok: true, banned: u.banned });
});
route('POST', '/api/admin/users/:id/pin', { admin: true }, (c) => {
  const u = db.users[String(c.params.id).toUpperCase()];
  if (!u) throw new HttpError(404, 'No user with that ID');
  const pin = String(c.body.pin || '');
  if (!/^\d{4,8}$/.test(pin)) throw bad('PIN must be 4-8 digits');
  u.pin = hashSecret(pin); save();
  json(c.res, 200, { ok: true });
});

route('GET', '/api/admin/orders', { admin: true }, (c) => {
  const st = c.query.get('status');
  let l = db.orders;
  if (st && st !== 'all') l = l.filter((o) => o.status === st);
  json(c.res, 200, l.slice(-300).reverse().map((o) => ({ ...pubOrder(o), userId: o.userId, username: o.username })));
});
route('POST', '/api/admin/orders/:id/status', { admin: true }, (c) => {
  const o = db.orders.find((x) => x.id === c.params.id);
  if (!o) throw new HttpError(404, 'Order not found');
  const st = String(c.body.status);
  if (!['pending', 'processing', 'completed', 'cancelled'].includes(st)) throw bad('Bad status');
  if (['completed', 'cancelled'].includes(o.status) && st !== o.status) throw bad('Order is already ' + o.status);
  if (st === 'cancelled' && o.cost > 0 && o.status !== 'cancelled') {
    const u = db.users[o.userId];
    u.balance += o.cost;
    ledger(u, o.cost, `Refund ${o.id}`, 'admin');
    pushUser(u.id, 'balance', { balance: pesos(u.balance), delta: pesos(o.cost) });
  }
  o.status = st; o.updatedAt = now();
  save();
  pushUser(o.userId, 'order', { id: o.id, status: st });
  json(c.res, 200, { ok: true });
});

route('GET', '/api/admin/chats', { admin: true }, (c) => {
  const l = Object.entries(db.chats).filter(([, t]) => t.msgs.length).map(([id, t]) => ({
    userId: id, username: (db.users[id] || {}).username || id, unread: t.unreadAdmin, last: t.last,
    lastText: t.msgs[t.msgs.length - 1].text.slice(0, 80),
  })).sort((a, b) => b.last - a.last);
  json(c.res, 200, l);
});
route('GET', '/api/admin/chats/:id', { admin: true }, (c) => {
  const t = db.chats[c.params.id];
  if (!t) return json(c.res, 200, { messages: [] });
  t.unreadAdmin = 0; save();
  json(c.res, 200, { messages: t.msgs.slice(-200), summary: summary() });
});
route('POST', '/api/admin/chats/:id', { admin: true }, (c) => {
  const u = db.users[c.params.id];
  if (!u) throw new HttpError(404, 'User not found');
  const text = str(c.body.text, 1000, 1);
  const t = thread(u.id);
  const m = { id: t.msgs.length + 1, from: 'admin', text, ts: now() };
  t.msgs.push(m); t.unreadUser++; t.unreadAdmin = 0; t.last = m.ts;
  save();
  pushUser(u.id, 'chat', m);
  json(c.res, 200, { message: m });
});

route('GET', '/api/admin/feedback', { admin: true }, (c) => json(c.res, 200, db.feedback.slice(-300).reverse()));
route('POST', '/api/admin/feedback/:id', { admin: true }, (c) => {
  const f = db.feedback.find((x) => x.id === c.params.id);
  if (!f) throw new HttpError(404, 'Not found');
  if (c.body.delete) db.feedback.splice(db.feedback.indexOf(f), 1);
  else {
    if (['new', 'seen', 'resolved'].includes(c.body.status)) f.status = c.body.status;
    if (typeof c.body.public === 'boolean') f.public = f.type === 'feedback' ? c.body.public : false;
  }
  save();
  json(c.res, 200, { ok: true, summary: summary() });
});

route('GET', '/api/admin/settings', { admin: true }, (c) => json(c.res, 200, db.settings));
route('POST', '/api/admin/settings', { admin: true }, (c) => {
  const s = db.settings, b = Object.assign({}, s, c.body);
  const int = (v, lo, hi, label) => { const n = Math.floor(Number(v)); if (!Number.isFinite(n) || n < lo || n > hi) throw bad(`${label} must be ${lo}-${hi}`); return n; };
  s.freeShares = int(b.freeShares, 1, 10000, 'Free shares');
  s.maxFreePerIp = int(b.maxFreePerIp, 1, 100, 'Free claims per IP');
  s.maxShares = int(b.maxShares, 100, 10000000, 'Max shares');
  s.minTopup = int(b.minTopup, 1, 100000, 'Min top-up');
  s.maxTopup = int(b.maxTopup, s.minTopup, 10000000, 'Max top-up');
  if (!Array.isArray(b.tiers) || !b.tiers.length || b.tiers.length > 6) throw bad('Add 1-6 price tiers');
  s.tiers = b.tiers.map((t) => {
    const price = Number(t.price);
    if (!(price > 0 && price <= 1000)) throw bad('Tier price must be > 0');
    return { name: str(String(t.name || ''), 20, 1), minShares: int(t.minShares, 1, 10000000, 'Tier min shares'), price };
  }).sort((a, z) => a.minShares - z.minShares);
  if (b.gcash) s.gcash = { name: str(String(b.gcash.name || ''), 40, 1), mobile: str(String(b.gcash.mobile || ''), 30, 1), note: String(b.gcash.note || '').slice(0, 120) };
  save();
  json(c.res, 200, s);
});
route('POST', '/api/admin/qr', { admin: true, maxBody: 9 * 1048576 }, (c) => {
  const { buf, ext } = decodeImage(c.body.image, 6 * 1048576);
  for (const e of ['jpg', 'png', 'webp']) { try { fs.unlinkSync(path.join(UPLOADS, 'qr.' + e)); } catch { /* none */ } }
  fs.writeFileSync(path.join(UPLOADS, 'qr.' + ext), buf);
  db.settings.qrVersion++;
  save();
  json(c.res, 200, { qr: '/qr?v=' + db.settings.qrVersion });
});
route('POST', '/api/admin/password', { admin: true }, (c) => {
  if (!verifySecret(String(c.body.current || ''), db.admin)) throw new HttpError(401, 'Current password is wrong');
  const np = String(c.body.next || '');
  if (np.length < 10) throw bad('New password must be at least 10 characters');
  db.admin = hashSecret(np); saveNow();
  adminSessions.clear();
  json(c.res, 200, { ok: true });
});

/* ------------------------------------------------------------ static */
function res_file(res, file, type, extra = {}) {
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size, ...extra });
    fs.createReadStream(file).pipe(res);
  });
}
function serveDir(res, base, rel, cache) {
  const file = path.normalize(path.join(base, rel));
  if (!file.startsWith(base + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  res_file(res, file, MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', { 'Cache-Control': cache });
}
function serveQr(res) {
  for (const e of ['jpg', 'png', 'webp']) {
    const f = path.join(UPLOADS, 'qr.' + e);
    if (fs.existsSync(f)) return res_file(res, f, MIME['.' + e], { 'Cache-Control': 'public, max-age=300' });
  }
  res_file(res, path.join(PUBLIC, 'img', 'gcash-qr.jpg'), 'image/jpeg', { 'Cache-Control': 'public, max-age=300' });
}

function serveHtmlPage(res, file, nonce, cache = 'no-store') {
  const html = fs.readFileSync(file, 'utf8').replaceAll('{{NONCE}}', nonce);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': cache });
  res.end(html);
}

/* ------------------------------------------------------------ server */
const server = http.createServer(async (req, res) => {
  const nonce = crypto.randomBytes(18).toString('base64');
  secHeaders(res, nonce);
  try {
    const url = new URL(req.url, 'http://x');
    let pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch { throw bad('Bad URL'); }
    if (pathname.includes('\0')) throw bad('Bad URL');
    const ip = clientIp(req);
    const cookies = parseCookies(req);
    let deviceId = cookies.sv_d;
    if (!/^[a-f0-9]{32}$/.test(deviceId || '')) {
      deviceId = crypto.randomBytes(16).toString('hex');
      setCookie(res, 'sv_d', deviceId, { maxAge: 63072000 });
    }

    if (pathname.startsWith('/api/')) {
      if (limited('g:' + ip, 600, 60000)) throw new HttpError(429, 'Too many requests');
      const method = req.method;
      let match = null;
      for (const r of routes) {
        if (r.method !== method) continue;
        const m = r.re.exec(pathname);
        if (m) { match = { r, m }; break; }
      }
      if (!match) throw new HttpError(404, 'Not found');
      const { r, m } = match;
      const params = {};
      r.keys.forEach((k, i) => { params[k] = m[i + 1]; });
      // CSRF guard on state-changing calls
      if (method !== 'GET') {
        if (req.headers['x-requested-with'] !== 'selov') throw new HttpError(403, 'Forbidden');
        const origin = req.headers.origin;
        if (origin) { let oh = ''; try { oh = new URL(origin).host; } catch { /* */ } if (oh !== req.headers.host) throw new HttpError(403, 'Forbidden'); }
      }
      const ctx = { req, res, ip, deviceId, params, query: url.searchParams, body: {}, user: null };
      if (r.opts.admin === true || r.opts.admin === undefined && r.opts.auth === 'admin') {
        if (!isAdmin(req)) throw new HttpError(401, 'Admin login required');
      } else if (r.opts.admin === 'public') {
        if (limited('al:' + ip, 30, 600000)) throw new HttpError(429, 'Too many requests');
      }
      if (r.opts.auth === 'user') {
        ctx.user = getUserFromReq(req);
        if (!ctx.user) throw new HttpError(401, 'Please log in first');
      }
      if (r.opts.rl && limited(`${r.opts.rl[0]}:${ip}`, r.opts.rl[1], r.opts.rl[2])) throw new HttpError(429, 'Too many requests. Please slow down.');
      if (method === 'POST') {
        const raw = await readBody(req, r.opts.maxBody || 64 * 1024);
        if (raw.length) {
          if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw bad('JSON required');
          try { ctx.body = JSON.parse(raw.toString('utf8')); } catch { throw bad('Invalid JSON'); }
          if (ctx.body === null || typeof ctx.body !== 'object') throw bad('Invalid JSON');
        }
      }
      return await r.fn(ctx);
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed');

    // ----- admin pages (dashboard only after a valid session)
    if (pathname === ADMIN_PATH || pathname === ADMIN_PATH + '/') {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');
      const page = isAdmin(req) ? 'adminsecretwow.html' : 'login.html';
      return serveHtmlPage(res, path.join(ADMIN_DIR, page), nonce);
    }
    if (pathname === '/qr') return serveQr(res);

    // ----- public site
    if (pathname === '/' || pathname === '/index.html') {
      return serveHtmlPage(res, path.join(ROOT, 'index.html'), nonce, 'public, max-age=300');
    }
    if (pathname === '/login.html' || pathname === '/register.html' || pathname === '/chat.html') {
      return serveHtmlPage(res, path.join(ROOT, pathname.slice(1)), nonce);
    }
    if (pathname.startsWith('/img/')) return serveDir(res, PUBLIC, pathname, 'public, max-age=300');
    if (pathname.startsWith('/assets/')) return serveDir(res, path.join(ROOT, 'assets'), pathname.slice(8), 'public, max-age=3600');
    if (/^\/media\/pf-[a-z0-9-]+\.(jpg|png|webp)$/.test(pathname)) return serveDir(res, UPLOADS, pathname.slice(7), 'public, max-age=86400, immutable');
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    if (!res.headersSent) json(res, status, { error: status === 500 ? 'Server error' : e.message });
    else res.end();
  }
});
server.requestTimeout = 60000;
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`\nPort ${PORT} is already in use (another copy of the server is probably running).\nClose it, or use another port:  PORT=3001 node server.js   (Windows: set PORT in .env)\n`);
  else if (e.code === 'EACCES') console.error(`\nNot allowed to use port ${PORT}. Try a port above 1024, e.g. PORT=3000.\n`);
  else console.error(e);
  process.exit(1);
});
server.listen(PORT, HOST, () => {
  console.log(`Selov asx running → http://localhost:${PORT}   (admin: ${ADMIN_PATH})`);
});
