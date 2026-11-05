'use strict';
require('dotenv').config();
const path = require('path'), fs = require('fs'), crypto = require('crypto');
const express = require('express'), cookieParser = require('cookie-parser'), http = require('http'), https = require('https');
const jwt = require('jsonwebtoken'), rateLimit = require('express-rate-limit'), helmet = require('helmet');
const { connect, FIELDS, q } = require('./db');

/* ---------- Configuration (see .env.example) ---------- */
const PORT = parseInt(process.env.PORT, 10) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const DATA = path.resolve(__dirname, process.env.DATA_DIR || 'data');   // SQLite file + auto-generated secret
const COOKIE_SECURE = (process.env.COOKIE_SECURE || 'auto').toLowerCase();   // auto = 'Secure' cookie only over HTTPS
const SESSION_HOURS = parseInt(process.env.SESSION_HOURS, 10) || 8;
// Only two statuses exist. Older values (Active / Inactive / Spare / Decommissioned) are mapped automatically.
const STATUSES = ['In use', 'Not in use'];
const normStatus = v => { const t = String(v || '').trim().toLowerCase(); return !t || ['in use', 'in-use', 'inuse', 'active'].includes(t) ? 'In use' : 'Not in use'; };
const ROLES = ['admin', 'user', 'viewer'];
fs.mkdirSync(DATA, { recursive: true });

let SECRET = process.env.JWT_SECRET;                       // set JWT_SECRET when running more than one instance
if (!SECRET) {
  const f = path.join(DATA, '.secret');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  SECRET = fs.readFileSync(f, 'utf8');
}

/* ---------- Helpers ---------- */
const COLS = ['id', ...FIELDS].map(q).join(',');
const SQL = {
  all: `SELECT ${COLS} FROM items`,
  one: `SELECT ${COLS} FROM items WHERE id=?`,
  serial: 'SELECT id FROM items WHERE lower(serial)=lower(?) AND id<>?',
  slot: 'SELECT id FROM items WHERE serial=\'\' AND lower(location)=lower(?) AND lower("row")=lower(?) AND lower(rack)=lower(?) AND lower(u)=lower(?) AND lower(model)=lower(?) AND id<>?',
  insert: `INSERT INTO items(id,${FIELDS.map(q).join(',')},updated_by) VALUES(${Array(FIELDS.length + 2).fill('?').join(',')})`,
  update: `UPDATE items SET ${FIELDS.map(f => `${q(f)}=?`).join(',')},updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`,
};
const insertVals = (o, id, by) => [id, ...FIELDS.map(f => o[f]), by];
const newId = () => Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') });
const checkPw = (pw, u) => { const a = crypto.scryptSync(pw, u.salt, 64), b = Buffer.from(u.hash, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const serialValue = value => String(value ?? '').trim();
const serialKey = value => serialValue(value).toLowerCase();
const hasSerial = value => serialValue(value).length > 0;
const clean = b => {
  const o = {};
  FIELDS.forEach(f => o[f] = String(b[f] ?? '').trim().slice(0, 500));
  o.serial = serialValue(b.serial).slice(0, 500);
  o.pduA = b.pduA ? '1' : ''; o.pduB = b.pduB ? '1' : '';
  o.status = normStatus(o.status);
  return o;
};
/* Duplicate rule: a serialised device is identified only by its serial number.
   The model and rack position are deliberately ignored when a serial exists, so
   identical devices with different serials remain separate inventory records.
   Position matching applies only when both records have no serial. */
const findDup = async (h, o, ex = '') => {
  if (hasSerial(o.serial)) return (await h.get(SQL.serial, [serialValue(o.serial), ex])) ? 'serial' : null;
  if (!hasSerial(o.serial) && o.rack && o.u) return (await h.get(SQL.slot, [o.location, o.row, o.rack, o.u, o.model, ex])) ? 'slot' : null;
  return null;
};
const dupKey = o => hasSerial(o.serial) ? 's:' + serialKey(o.serial) : (o.rack && o.u ? 'p:' + [o.location, o.row, o.rack, o.u, o.model].map(x => String(x).trim().toLowerCase()).join('|') : null);
const noPos = o => !hasSerial(o.serial) && !(o.rack && o.u);       // cannot be matched by serial or by rack position
const contentKey = o => [o.location, o.row, o.rack, o.u, o.model, o.purpose, o.assetTag, o.owner, o.user].map(x => String(x).toLowerCase()).join('|');
const DUP_MSG = { serial: 'This serial number already exists in the inventory.', slot: 'An identical item already exists at this location, row, rack and U position.' };
const validPw = p => typeof p === 'string' && p.length >= 8 && p.length <= 200;
const validUser = u => typeof u === 'string' && /^[a-z0-9._-]{2,40}$/.test(u);

async function main() {
  console.log(process.env.DATABASE_URL ? 'Connecting to the online database (DATABASE_URL)...' : 'Opening the local SQLite database...');
  const db = await connect(process.env.DATABASE_URL ? { url: process.env.DATABASE_URL } : { file: path.join(DATA, 'inventory.db') });
  // One-time, repeatable clean-up of old statuses (does nothing once all rows use the two new values).
  await db.run("UPDATE items SET status='In use' WHERE status='Active'");
  await db.run("UPDATE items SET status='Not in use' WHERE status IS NULL OR status NOT IN ('In use','Not in use')");
  const userCount = async () => Number((await db.get('SELECT COUNT(*) AS n FROM users')).n);
  const getUser = u => db.get('SELECT username,salt,hash,role FROM users WHERE username=?', [u]);
  const setCookie = (req, res, username) => res.cookie('token', jwt.sign({ u: username }, SECRET, { expiresIn: SESSION_HOURS + 'h' }),
    { httpOnly: true, sameSite: 'strict', secure: COOKIE_SECURE === 'true' ? true : COOKIE_SECURE === 'false' ? false : req.secure, maxAge: SESSION_HOURS * 3600e3 });
  const currentUser = async req => { try { const t = jwt.verify(req.cookies.token, SECRET); return (await db.get('SELECT username,role FROM users WHERE username=?', [t.u])) || null; } catch { return null; } };
  const auth = async (req, res, next) => { const u = await currentUser(req); if (!u) return res.status(401).json({ error: 'Please sign in again.' }); req.user = u; next(); };
  const need = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Your role does not allow this action.' });
  const wrap = fn => async (req, res) => { try { await fn(req, res); } catch (e) { console.error(e); if (!res.headersSent) res.status(500).json({ error: 'Server error' }); } };

  const app = express();
  app.set('trust proxy', parseInt(process.env.TRUST_PROXY, 10) || 0);
  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'], scriptSrcAttr: ["'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], upgradeInsecureRequests: null } } }));
  app.use(express.json({ limit: '10mb' }));
  app.use(cookieParser());
  app.use(express.static(path.join(__dirname, 'public')));
  app.get('/healthz', wrap(async (req, res) => { await db.get('SELECT 1 AS ok'); res.json({ ok: true, db: db.kind }); }));

  const loginLimit = rateLimit({ windowMs: 15 * 60e3, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a few minutes.' } });
  const aiLimit = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many assistant requests. Please wait a moment.' } });
  const kimiRequest = (url, body, caPath, apiKey) => new Promise((resolve, reject) => {
    const target = new URL(url), secure = target.protocol === 'https:';
    const transport = secure ? https : http;
    const req = transport.request(target, {
      method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, apiKey ? { Authorization: 'Bearer ' + apiKey } : {}),
      ca: secure && caPath ? fs.readFileSync(path.resolve(__dirname, caPath)) : undefined,
      timeout: 30000
    }, response => {
      let raw = ''; response.setEncoding('utf8');
      response.on('data', chunk => { raw += chunk; });
      response.on('end', () => { try { resolve({ status: response.statusCode || 502, payload: JSON.parse(raw || '{}') }); } catch { reject(new Error('AI service returned invalid JSON.')); } });
    });
    req.on('timeout', () => req.destroy(new Error('AI service timed out.')));
    req.on('error', reject); req.end(body);
  });

  /* --- Auth --- */
  app.get('/api/auth/status', wrap(async (req, res) => res.json({ setup: (await userCount()) === 0, user: await currentUser(req) })));
  app.post('/api/auth/setup', loginLimit, wrap(async (req, res) => {
    if ((await userCount()) > 0) return res.status(403).json({ error: 'Setup already completed.' });
    const username = String(req.body.username || '').trim().toLowerCase(), pw = req.body.password;
    if (!validUser(username)) return res.status(400).json({ error: 'Username: 2–40 characters (letters, numbers, . _ -).' });
    if (!validPw(pw)) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const h = hashPw(pw); await db.run('INSERT INTO users(username,salt,hash,role) VALUES(?,?,?,?)', [username, h.salt, h.hash, 'admin']);
    setCookie(req, res, username); res.json({ username, role: 'admin' });
  }));
  app.post('/api/auth/login', loginLimit, wrap(async (req, res) => {
    const username = String(req.body.username || '').trim().toLowerCase(), pw = String(req.body.password || '');
    const u = await getUser(username);
    if (!u || !checkPw(pw, u)) { console.log(`[login] failed for "${username}" (${u ? 'wrong password' : 'no such user'})`); return res.status(401).json({ error: 'Incorrect username or password.' }); }
    setCookie(req, res, username); res.json({ username, role: u.role });
  }));
  app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
  app.post('/api/me/password', auth, wrap(async (req, res) => {
    const u = await getUser(req.user.username);
    if (!checkPw(String(req.body.current || ''), u)) return res.status(400).json({ error: 'Current password is incorrect.' });
    if (!validPw(req.body.next)) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    const h = hashPw(req.body.next); await db.run('UPDATE users SET salt=?, hash=? WHERE username=?', [h.salt, h.hash, u.username]); res.json({ ok: true });
  }));

  /* --- Inventory --- */
  app.get('/api/items', auth, wrap(async (req, res) => res.json(await db.all(SQL.all))));
  app.post('/api/items', auth, need('admin', 'user'), wrap(async (req, res) => {
    const o = clean(req.body);
    if (!o.model) return res.status(400).json({ error: 'Equipment / Model is required.' });
    const dup = await findDup(db, o); if (dup) return res.status(409).json({ error: DUP_MSG[dup] });
    const id = newId(); await db.run(SQL.insert, insertVals(o, id, req.user.username)); res.status(201).json(await db.get(SQL.one, [id]));
  }));
  app.put('/api/items/:id', auth, need('admin', 'user'), wrap(async (req, res) => {
    if (!(await db.get(SQL.one, [req.params.id]))) return res.status(404).json({ error: 'Item not found.' });
    const o = clean(req.body);
    if (!o.model) return res.status(400).json({ error: 'Equipment / Model is required.' });
    const dup = await findDup(db, o, req.params.id); if (dup) return res.status(409).json({ error: DUP_MSG[dup] });
    await db.run(SQL.update, [...FIELDS.map(f => o[f]), req.user.username, req.params.id]); res.json(await db.get(SQL.one, [req.params.id]));
  }));
  app.delete('/api/items/:id', auth, need('admin'), wrap(async (req, res) => { await db.run('DELETE FROM items WHERE id=?', [req.params.id]); res.json({ ok: true }); }));
  app.post('/api/items/delete', auth, need('admin'), wrap(async (req, res) => {
    const ids = Array.isArray(req.body.ids) ? req.body.ids.map(String) : [];
    await db.tx(async t => { for (const i of ids) await t.run('DELETE FROM items WHERE id=?', [i]); }); res.json({ deleted: ids.length });
  }));
  app.post('/api/items/dedupe', auth, need('admin'), wrap(async (req, res) => {
    const seen = new Set(), extra = [];
    (await db.all(SQL.all)).sort((a, b) => a.id < b.id ? -1 : 1).forEach(r => { const k = dupKey(r); if (!k) return; if (seen.has(k)) extra.push(r.id); else seen.add(k); });
    if (req.body.dry) return res.json({ found: extra.length });
    await db.tx(async t => { for (const id of extra) await t.run('DELETE FROM items WHERE id=?', [id]); });
    res.json({ removed: extra.length });
  }));
  app.delete('/api/items', auth, need('admin'), wrap(async (req, res) => { await db.run('DELETE FROM items'); res.json({ ok: true }); }));
  app.post('/api/items/import', auth, need('admin', 'user'), wrap(async (req, res) => {
    const rows = Array.isArray(req.body.items) ? req.body.items : [];
    let added = 0, skippedSerial = 0, skippedSlot = 0, skippedSame = 0, conflictCount = 0;
    const conflicts = [], pos = x => `${x.location || '-'} row ${x.row || '-'} rack ${x.rack || '-'} U${x.u || '-'}`, same = (p, q) => [p.location, p.row, p.rack, p.u].every((v, i) => String(v).toLowerCase() === String([q.location, q.row, q.rack, q.u][i]).toLowerCase());
    const have = new Map(), seenNow = new Map();            // rows with no serial and no rack/U: skip as many copies as already exist
    (await db.all(SQL.all)).forEach(r => { if (noPos(r)) { const k = contentKey(r); have.set(k, (have.get(k) || 0) + 1); } });
    await db.tx(async t => {
      for (const r of rows) {
        const o = clean(r);
        if (!o.model) { skippedSlot++; continue; }
        if (noPos(o)) { const k = contentKey(o), n = (seenNow.get(k) || 0) + 1; seenNow.set(k, n); if (n <= (have.get(k) || 0)) { skippedSame++; continue; } }
        else {
          const dup = await findDup(t, o);
          if (dup === 'serial') {
            skippedSerial++;
            const ex = await t.get('SELECT location,"row",rack,u FROM items WHERE lower(serial)=lower(?)', [o.serial]);
            if (ex && !same(ex, o)) { conflictCount++; if (conflicts.length < 15) conflicts.push({ serial: o.serial, incoming: pos(o), existing: pos(ex) }); }
            continue;
          }
          if (dup) { skippedSlot++; continue; }
        }
        await t.run(SQL.insert, insertVals(o, newId(), req.user.username)); added++;
      }
    });
    res.json({ added, skipped: skippedSerial + skippedSlot + skippedSame, skippedSerial, skippedSlot, skippedSame, conflictCount, conflicts });
  }));

  /* --- Users (admin only) --- */
  app.get('/api/users', auth, need('admin'), wrap(async (req, res) => res.json(await db.all('SELECT username,role FROM users ORDER BY username'))));
  app.post('/api/users', auth, need('admin'), wrap(async (req, res) => {
    const username = String(req.body.username || '').trim().toLowerCase(), { password, role } = req.body;
    if (!validUser(username)) return res.status(400).json({ error: 'Username: 2–40 characters (letters, numbers, . _ -).' });
    if (!validPw(password)) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    if (await getUser(username)) return res.status(409).json({ error: 'That username already exists.' });
    const h = hashPw(password); await db.run('INSERT INTO users(username,salt,hash,role) VALUES(?,?,?,?)', [username, h.salt, h.hash, role]); res.status(201).json({ username, role });
  }));
  app.patch('/api/users/:u', auth, need('admin'), wrap(async (req, res) => {
    if (req.params.u === req.user.username) return res.status(400).json({ error: 'You cannot change your own role.' });
    if (!(await getUser(req.params.u))) return res.status(404).json({ error: 'User not found.' });
    if (!ROLES.includes(req.body.role)) return res.status(400).json({ error: 'Invalid role.' });
    await db.run('UPDATE users SET role=? WHERE username=?', [req.body.role, req.params.u]); res.json({ ok: true });
  }));
  app.delete('/api/users/:u', auth, need('admin'), wrap(async (req, res) => {
    if (req.params.u === req.user.username) return res.status(400).json({ error: 'You cannot remove your own account.' });
    await db.run('DELETE FROM users WHERE username=?', [req.params.u]); res.json({ ok: true });
  }));

  /* --- 3D data center view (read-only; devices are added through /api/items) --- */
  app.get('/api/locations', auth, wrap(async (req, res) => {
    const rows = await db.all('SELECT DISTINCT location, "row" FROM items ORDER BY location, "row"');
    res.json({ locations: [...new Set(rows.map(r => r.location).filter(Boolean))], rows: rows.filter(r => r.location && r.row).map(r => ({ location: r.location, row: r.row })) });
  }));
  app.get('/api/racks', auth, wrap(async (req, res) => {
    const { location, row } = req.query;
    if (!location || !row) return res.status(400).json({ error: 'location and row required' });
    {
      const items = await db.all(
        'SELECT id, location, "row", rack, u, model, serial, item, status, purpose, assetTag FROM items WHERE location=? AND "row"=? ORDER BY rack, CAST(u AS INTEGER) DESC',
        [location, row]
      );
      const racks = {};
      items.forEach(item => {
        const rackNum = item.rack || '0';
        const rackId = 'R' + rackNum;
        if (!racks[rackId]) racks[rackId] = { id: rackId, location: item.location, row: item.row, rack: rackNum, status: 'Spare', equipment: [] };
        if (item.model === 'Empty slot') return;
        racks[rackId].status = 'Active';
        const m = String(item.u || '').match(/^(\d+)\s*[-–]\s*(\d+)$/);
        const a = m ? +m[1] : parseInt(item.u) || 1, b = m ? +m[2] : a;
        const info = inferEquipmentType(item);
        racks[rackId].equipment.push({
          id: item.id,
          label: item.model || item.item || item.serial || 'Unknown',
          type: info.type, kind: info.kind,
          uPosition: Math.min(a, b), uSize: Math.abs(b - a) + 1,
          serial: item.serial, status: item.status, purpose: item.purpose, assetTag: item.assetTag
        });
      });
      res.json(Object.values(racks));
    }
  }));
  app.put('/api/racks/rename', auth, need('admin', 'user'), wrap(async (req, res) => {
    const location = String(req.body.location || '').trim();
    const row = String(req.body.row || '').trim();
    const current = String(req.body.current || '').trim();
    const next = String(req.body.next || '').trim();
    if (!location || !row || !current || !next) return res.status(400).json({ error: 'Location, row, current rack name and new rack name are required.' });
    if (current === next) return res.status(400).json({ error: 'The new rack name must be different.' });
    const existing = await db.get('SELECT 1 FROM items WHERE location=? AND "row"=? AND rack=? LIMIT 1', [location, row, next]);
    if (existing) return res.status(409).json({ error: 'Rack ' + next + ' already exists in this row.' });
    const updated = await db.run('UPDATE items SET rack=?, updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE location=? AND "row"=? AND rack=?', [next, req.user.username, location, row, current]);
    if (!updated) return res.status(404).json({ error: 'Rack ' + current + ' was not found in this row.' });
    res.json({ ok: true, updated, rack: next });
  }));
  app.delete('/api/racks', auth, need('admin', 'user'), wrap(async (req, res) => {
    const location = String(req.body.location || '').trim();
    const row = String(req.body.row || '').trim();
    const rack = String(req.body.rack || '').trim();
    if (!location || !row || !rack) return res.status(400).json({ error: 'Location, row and rack are required.' });
    const removed = await db.run('DELETE FROM items WHERE location=? AND "row"=? AND rack=?', [location, row, rack]);
    if (!removed) return res.status(404).json({ error: 'Rack ' + rack + ' was not found in this row.' });
    res.json({ ok: true, removed, rack });
  }));

  function inferEquipmentType(item) {
    const t = ((item.model || '') + ' ' + (item.item || '') + ' ' + (item.purpose || '')).toLowerCase();
    if (t.includes('firewall')) return { type: 'network', kind: 'firewall' };
    if (t.includes('router')) return { type: 'network', kind: 'router' };
    if (t.includes('switch') || t.includes('kemp') || t.includes('load balancer')) return { type: 'network', kind: 'switch' };
    if (t.includes('storage') || t.includes('stor')) return { type: 'storage', kind: 'storage' };
    if (t.includes('pdu')) return { type: 'pdu', kind: 'pdu' };
    return { type: 'server', kind: 'server' };
  }

  /* ---------- NEW: Local NLP + Inventory query engine ---------- */
  const normalize = t => String(t || '').toLowerCase()
    .replace(/[._\-\/\\]/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/#/g, ' ')
    .trim();

  const queryCache = new Map();
  const CACHE_MS = 30_000; // reuse computed summaries for 30 s

  async function loadContext() {
    const key = 'context';
    const now = Date.now();
    const cached = queryCache.get(key);
    if (cached && now - cached.ts < CACHE_MS) return cached.data;

    const rows = await db.all(
      'SELECT location, "row", rack, u, model, serial, status, purpose, owner, assetTag, user, item, pduA, pduB FROM items ORDER BY location, "row", rack, u'
    );

    // canonical values
    const locations = [...new Set(rows.map(r => String(r.location || '').trim()).filter(Boolean))].sort();
    const models = [...new Set(rows.map(r => String(r.model || '').trim()).filter(Boolean))].sort();
    const owners = [...new Set(rows.map(r => String(r.owner || '').trim()).filter(Boolean))].sort();
    const users = [...new Set(rows.map(r => String(r.user || '').trim()).filter(Boolean))].sort();

    // per-rack summary
    const rackMap = new Map();
    rows.forEach(item => {
      const loc = String(item.location || '').trim() || '(no location)';
      const row = String(item.row || '').trim() || '(no row)';
      const rack = String(item.rack || '').trim();
      if (!rack) return;
      const key = `${loc}|${row}|${rack}`;
      if (!rackMap.has(key)) rackMap.set(key, { location: loc, row, rack, devices: 0, occupiedU: new Set(), emptySlots: 0, models: new Set(), statuses: { 'In use': 0, 'Not in use': 0 } });
      const s = rackMap.get(key);
      const isEmpty = String(item.model || '').trim().toLowerCase() === 'empty slot';
      if (isEmpty || !String(item.model || '').trim()) {
        s.emptySlots++;
        return;
      }
      s.devices++;
      s.models.add(String(item.model).trim());
      const st = normStatus(item.status);
      s.statuses[st] = (s.statuses[st] || 0) + 1;
      const match = String(item.u || '').match(/^(\d+)\s*[-–]\s*(\d+)$/);
      const start = match ? Number(match[1]) : parseInt(item.u, 10);
      const end = match ? Number(match[2]) : start;
      if (Number.isFinite(start) && Number.isFinite(end)) {
        for (let u = Math.min(start, end); u <= Math.max(start, end); u++) s.occupiedU.add(u);
      }
    });

    const racks = [...rackMap.values()].map(r => ({
      location: r.location,
      row: r.row,
      rack: r.rack,
      devices: r.devices,
      emptySlots: r.emptySlots,
      occupiedU: [...r.occupiedU].sort((a, b) => a - b),
      vacant: r.devices === 0,
      models: [...r.models].sort(),
      statuses: r.statuses
    }));

    // per-location summary
    const byLocation = {};
    rows.forEach(r => {
      const loc = String(r.location || '').trim() || '(no location)';
      if (!byLocation[loc]) byLocation[loc] = { count: 0, 'In use': 0, 'Not in use': 0, racks: new Set(), rows: new Set() };
      byLocation[loc].count++;
      const st = normStatus(r.status);
      byLocation[loc][st]++;
      if (r.rack) byLocation[loc].racks.add(String(r.rack).trim());
      if (r.row) byLocation[loc].rows.add(String(r.row).trim());
    });

    const summary = {
      total: rows.length,
      statuses: { 'In use': 0, 'Not in use': 0 },
      locations,
      models,
      owners,
      users,
      racks,
      byLocation: Object.fromEntries(Object.entries(byLocation).map(([k, v]) => [k, {
        count: v.count, 'In use': v['In use'], 'Not in use': v['Not in use'],
        racks: [...v.racks].sort(), rows: [...v.rows].sort()
      }]))
    };
    rows.forEach(r => { summary.statuses[normStatus(r.status)] = (summary.statuses[normStatus(r.status)] || 0) + 1; });

    const data = { rows, summary, locations, models };
    queryCache.set(key, { ts: now, data });
    return data;
  }

  function extractEntities(text, knownLocations, knownModels) {
    const n = normalize(text);

    // status
    let status = null;
    if (/(not in use|inactive|spare|decommissioned|offline)/.test(n)) status = 'Not in use';
    else if (/(in use|active|online|live|production)/.test(n)) status = 'In use';

    // intent markers
    const intent = {
      count: /\b(how many|count|total|number of)\b/.test(n),
      list: /\b(list|show|display|give me|what are|find|search|where is|where are)\b/.test(n),
      vacant: /\b(vacant|empty|free|available rack|spare rack|no devices)\b/.test(n),
      compare: /\b(compare|versus|vs|difference between|between)\b/.test(n),
      summary: /\b(summary|overview|summarize|status|inventory report)\b/.test(n),
      racks: /\b(rack|racks|cabinet|cabinets)\b/.test(n)
    };

    // locations with fuzzy aliases (hdc4 = hdc dc 4 = hdc-4)
    const foundLocations = [];
    const locTokens = knownLocations.map(l => ({ raw: l, norm: normalize(l) }));
    for (const { raw, norm: ln } of locTokens) {
      if (n.includes(ln)) { foundLocations.push(raw); continue; }
      // alias: "hdc dc 4" -> "hdc4"
      const compressed = ln.replace(/\s+/g, '');
      if (n.includes(compressed)) { foundLocations.push(raw); continue; }
      // alias: "dc4" may map to a location that ends with 4
      const words = n.split(' ');
      if (words.some(w => w === compressed || w.replace(/dc/, '') === ln.replace(/dc/, ''))) foundLocations.push(raw);
    }

    // rows: "row 1", "row1", "r1"
    const rowMatches = [...n.matchAll(/\b(?:row|r)\s*(\d+)\b/g)].map(m => m[1]);
    const rows = [...new Set(rowMatches)];

    // racks: "rack 5", "rack5", "r5" (avoid clashing with row)
    const rackMatches = [...n.matchAll(/\b(?:rack)\s*(\d+)\b/g)].map(m => m[1]);
    const racks = [...new Set(rackMatches)];

    // U numbers
    const uMatches = [...n.matchAll(/\b(?:u|unit)\s*(\d+)\b/g)].map(m => m[1]);
    const units = [...new Set(uMatches)];

    // models
    const foundModels = knownModels.filter(m => n.includes(normalize(m)));

    // equipment type keywords
    const types = [];
    if (/\b(switch|switches)\b/.test(n)) types.push('switch');
    if (/\b(router|routers)\b/.test(n)) types.push('router');
    if (/\b(firewall|firewalls)\b/.test(n)) types.push('firewall');
    if (/\b(server|servers)\b/.test(n)) types.push('server');
    if (/\b(storage|san|nas)\b/.test(n)) types.push('storage');
    if (/\b(pdu|pdus)\b/.test(n)) types.push('pdu');

    // owner / user / asset
    let owner = null, asset = null;
    const ownerMatch = n.match(/\bowner\s+([a-z0-9._-]+)/);
    if (ownerMatch) owner = ownerMatch[1];
    const assetMatch = n.match(/\basset\s*(?:tag)?\s*([a-z0-9_-]+)/i);
    if (assetMatch) asset = assetMatch[1];

    return { status, intent, locations: [...new Set(foundLocations)], rows, racks, units, models: foundModels, types, owner, asset };
  }

  function matchesFilters(item, e) {
    const loc = String(item.location || '').trim().toLowerCase();
    if (e.locations.length && !e.locations.some(l => loc === normalize(l))) return false;
    if (e.status && normStatus(item.status) !== e.status) return false;
    if (e.rows.length && !e.rows.includes(String(item.row || '').trim())) return false;
    if (e.racks.length && !e.racks.includes(String(item.rack || '').trim())) return false;
    if (e.models.length) {
      const mod = normalize(item.model || '');
      if (!e.models.some(m => mod === normalize(m))) return false;
    }
    if (e.types.length) {
      const info = inferEquipmentType(item);
      if (!e.types.includes(info.kind)) return false;
    }
    if (e.owner && !normalize(item.owner || '').includes(e.owner)) return false;
    if (e.asset && !normalize(item.assetTag || '').includes(e.asset)) return false;
    return true;
  }

  function rackMatches(rack, e) {
    const loc = String(rack.location || '').trim().toLowerCase();
    if (e.locations.length && !e.locations.some(l => loc === normalize(l))) return false;
    if (e.rows.length && !e.rows.includes(String(rack.row || '').trim())) return false;
    if (e.racks.length && !e.racks.includes(String(rack.rack || '').trim())) return false;
    return true;
  }

  async function runLocalQuery(question, interpreted) {
    const { rows, summary, locations, models } = await loadContext();
    const e = interpreted || extractEntities(question, locations, models);

    // Rack questions must be answered from the rack summary, not counted as
    // inventory records. This also handles natural wording such as "how many
    // rack in total" and "number of racks in row 1".
    if (e.intent.racks && (e.intent.count || e.intent.list || e.intent.summary)) {
      const scopedRacks = summary.racks.filter(r => rackMatches(r, e));
      if (e.intent.count) {
        return {
          handled: true,
          answer: `${scopedRacks.length} rack(s)${e.locations.length ? ' in ' + e.locations.join(', ') : ''}${e.rows.length ? ' in row ' + e.rows.join(', ') : ''}.`
        };
      }
      if (!scopedRacks.length) return { handled: true, answer: 'No racks match the requested scope.' };
      return {
        handled: true,
        answer: `Showing ${Math.min(scopedRacks.length, 20)} of ${scopedRacks.length} rack(s):\n` +
          scopedRacks.slice(0, 20).map(r =>
            `• ${r.location}, row ${r.row}, rack ${r.rack}${r.vacant ? ' (vacant)' : ` (${r.devices} device(s))`}`
          ).join('\n') +
          (scopedRacks.length > 20 ? `\n… and ${scopedRacks.length - 20} more.` : '')
      };
    }

    // Vacant racks
    if (e.intent.vacant || (e.intent.list && /\b(vacant|empty|free)\b/.test(normalize(question)))) {
      const hits = summary.racks.filter(r => r.vacant && rackMatches(r, e));
      if (hits.length) {
        return {
          handled: true,
          answer: `Found ${hits.length} vacant rack(s)${e.locations.length ? ' in ' + e.locations.join(', ') : ''}:\n` +
            hits.slice(0, 20).map(r => `• ${r.location}, row ${r.row}, rack ${r.rack}`).join('\n') +
            (hits.length > 20 ? `\n… and ${hits.length - 20} more.` : '')
        };
      }
      return { handled: true, answer: 'No vacant racks match the requested scope.' };
    }

    // Count / list filtered items
    if (e.intent.count || e.intent.list || e.intent.summary) {
      const hits = rows.filter(r => matchesFilters(r, e));
      const total = hits.length;
      if (e.intent.count) {
        return { handled: true, answer: `${total} item(s) match.` + (e.locations.length ? ` Scope: ${e.locations.join(', ')}.` : '') };
      }
      if (total === 0) return { handled: true, answer: 'No matching items found.' };
      if (e.intent.list) {
        return {
          handled: true,
          answer: `Showing ${Math.min(total, 15)} of ${total} matching item(s):\n` +
            hits.slice(0, 15).map(r =>
              `• ${r.model || r.item || 'Unknown'} — ${r.location || '-'} row ${r.row || '-'} rack ${r.rack || '-'} U${r.u || '-'} (${normStatus(r.status)})`
            ).join('\n') +
            (total > 15 ? `\n… and ${total - 15} more.` : '')
        };
      }
    }

    // Summary / overview
    if (e.intent.summary) {
      const lines = [
        `Total inventory: ${summary.total} records.`,
        `Statuses: ${summary.statuses['In use']} in use, ${summary.statuses['Not in use']} not in use.`,
        `Locations: ${summary.locations.join(', ') || 'none'}.`,
        `Racks: ${summary.racks.length} (${summary.racks.filter(r => r.vacant).length} vacant).`
      ];
      return { handled: true, answer: lines.join('\n') };
    }

    // Comparison between locations
    if (e.intent.compare && e.locations.length >= 2) {
      const [a, b] = e.locations.slice(0, 2);
      const sa = summary.byLocation[a] || { count: 0, 'In use': 0, 'Not in use': 0 };
      const sb = summary.byLocation[b] || { count: 0, 'In use': 0, 'Not in use': 0 };
      return {
        handled: true,
        answer: `Comparison: ${a} vs ${b}\n` +
          `• ${a}: ${sa.count} items (${sa['In use']} in use, ${sa['Not in use']} not in use)\n` +
          `• ${b}: ${sb.count} items (${sb['In use']} in use, ${sb['Not in use']} not in use)`
      };
    }

    return { handled: false };
  }

  /* ---------- AI chat (enhanced with NLP + tools + fallback) ---------- */
  app.post('/api/ai/chat', auth, aiLimit, wrap(async (req, res) => {
    const question = String(req.body.message || '').trim().slice(0, 4000);
    if (!question) return res.status(400).json({ error: 'A question is required.' });
    const baseUrl = String(process.env.KIMI_URL || process.env.AI_BASE_URL || '').trim();
    const { locations, models } = await loadContext();
    let interpreted;
    if (baseUrl) {
      const endpoint = baseUrl.replace(/\/+$/, '').replace(/\/chat\/completions$/i, '') + '/chat/completions';
      const interpretationPrompt = [
        'Interpret the inventory question below. Return JSON only, with no markdown.',
        'Schema: {"kind":"rack|item|summary|concept|unknown","action":"count|list|vacant|compare|summary|none","locations":[],"rows":[],"racks":[],"models":[],"types":[],"status":null}',
        'Use kind=rack for cabinets, racks, enclosures, or rack units when the user asks about physical racks.',
        'Use action=count for any wording asking for a total, quantity, number, how-many, amount, or overall count.',
        'Use action=vacant for empty, free, unused, or available racks.',
        'Use action=list for requests to show, identify, name, or list records.',
        'Extract location, row, rack, model, equipment type, and status only when the user specifies them.',
        'Do not answer the question. Only classify it.',
        'Question: ' + question
      ].join('\n');
      try {
        const result = await kimiRequest(endpoint, JSON.stringify({
          model: process.env.KIMI_MODEL || process.env.AI_MODEL || 'gpt-4o-mini',
          temperature: 0,
          max_tokens: 300,
          messages: [{ role: 'system', content: interpretationPrompt }]
        }), process.env.KIMI_CA_CERT_PATH, process.env.KIMI_API_KEY || process.env.AI_API_KEY);
        const raw = result.payload && result.payload.choices && result.payload.choices[0] && result.payload.choices[0].message && result.payload.choices[0].message.content;
        const parsed = JSON.parse(String(raw || '').replace(/^```json\s*|\s*```$/gi, '').trim());
        const normalizeList = value => Array.isArray(value) ? value.map(v => String(v).trim()).filter(Boolean) : [];
        const fallback = extractEntities(question, locations, models);
        interpreted = Object.assign(fallback, {
          locations: normalizeList(parsed.locations),
          rows: normalizeList(parsed.rows),
          racks: normalizeList(parsed.racks),
          models: normalizeList(parsed.models),
          types: normalizeList(parsed.types),
          status: parsed.status || null,
          intent: Object.assign({}, fallback.intent, {
            count: parsed.action === 'count',
            list: parsed.action === 'list',
            vacant: parsed.action === 'vacant',
            summary: parsed.action === 'summary',
            racks: parsed.kind === 'rack'
          })
        });
      } catch (e) {
        console.warn('[ai] natural-language intent parsing failed:', e.message);
      }
    }
    const local = await runLocalQuery(question, interpreted);
    if (!baseUrl) {
      if (local.handled) return res.json({ answer: local.answer });
      return res.status(503).json({ error: 'AI is not configured. Set AI_BASE_URL in .env and restart the server.' });
    }
    const suppliedMessages = Array.isArray(req.body.messages) ? req.body.messages : [];
    const messages = suppliedMessages.slice(-10).map(m => ({
      role: m && m.role === 'assistant' ? 'assistant' : 'user',
      content: String(m && m.content || '').trim().slice(0, 4000)
    })).filter(m => m.content);
    if (!messages.length || messages[messages.length - 1].content !== question) messages.push({ role: 'user', content: question });

    const { rows, summary } = await loadContext();
    const entities = interpreted || extractEntities(question, locations, models);

    // Try a fast local answer first for obvious intents
    if (local.handled && (!process.env.AI_ALWAYS_USE_LLM || entities.intent.racks)) {
      // still optionally let the LLM polish it, but if the model fails we have a guaranteed answer
      const forcedLLM = /why|explain|suggest|recommend|should|advice/i.test(question);
      if (!forcedLLM) return res.json({ answer: local.answer });
    }

    // Build a compact, structured prompt instead of one giant JSON dump
    const racks = summary.racks.map(r => ({
      location: r.location, row: r.row, rack: r.rack, devices: r.devices,
      vacant: r.vacant, occupiedU: r.occupiedU, models: r.models.slice(0, 5)
    }));

    const topRecords = rows
      .filter(r => matchesFilters(r, entities))
      .slice(0, 50)
      .map(r => ({
        location: r.location, row: r.row, rack: r.rack, u: r.u,
        model: r.model, serial: r.serial, status: normStatus(r.status),
        purpose: r.purpose, owner: r.owner, assetTag: r.assetTag
      }));

    const toolSchema = {
      query_inventory: {
        description: 'Query the inventory database precisely.',
        parameters: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['count', 'list', 'vacant', 'summary', 'compare'], description: 'What to compute.' },
            location: { type: 'string', description: 'Exact location name, e.g. HDC4.' },
            row: { type: 'string', description: 'Row number.' },
            rack: { type: 'string', description: 'Rack number.' },
            status: { type: 'string', enum: ['In use', 'Not in use'], description: 'Status filter.' },
            model: { type: 'string', description: 'Exact model substring.' },
            equipmentType: { type: 'string', enum: ['switch', 'router', 'firewall', 'server', 'storage', 'pdu'], description: 'Equipment category.' }
          },
          required: ['action']
        }
      }
    };

    const system = [
      'You are MaxisBot, the data-center inventory analyst. Answer the user directly from the data below. Never ask the user to open another page or use exact keywords.',
      '',
      'RULES:',
      '1. Resolve names case-insensitively. HDC4, HDC DC 4, HDC-DC4 and "dc4" all refer to location HDC4 if HDC4 exists in the location list.',
      '2. "Row 1" means the row field equals "1". Do not confuse row with rack or location.',
      '3. For vacant/empty/free rack questions, use the rack summary. A rack with devices=0 is vacant.',
      '4. For counts, filters, comparisons and rankings, calculate from the data and show the number.',
      '5. When the user asks how many racks there are, count rack summary entries; never answer with item, device, or U-position counts.',
      '6. If data is missing, say exactly which field is missing. Do not invent facts.',
      '7. Keep answers concise (2-6 bullets).',
      '8. You may call query_inventory with the exact parameters if you need precise data; otherwise use the summaries provided.',
      '',
      'AVAILABLE TOOL:',
      JSON.stringify(toolSchema),
      '',
      'ENTITY EXTRACTION (from the user message):',
      JSON.stringify(entities),
      '',
      'INVENTORY SUMMARY:',
      `Total: ${summary.total} items. Statuses: ${summary.statuses['In use']} in use, ${summary.statuses['Not in use']} not in use.`,
      `Locations: ${summary.locations.join(', ') || 'none'}.`,
      `Rack summary (${racks.length} racks, ${racks.filter(r => r.vacant).length} vacant):`,
      ...racks.slice(0, 60).map(r => `  ${r.location} row ${r.row} rack ${r.rack}: ${r.devices} device(s)${r.vacant ? ' [VACANT]' : ''}`),
      racks.length > 60 ? `  … ${racks.length - 60} more racks omitted.` : '',
      '',
      'MATCHING RECORDS (top 50):',
      JSON.stringify(topRecords),
      '',
      'CURRENT UI VIEW:',
      JSON.stringify({
        location: String(req.body.context && req.body.context.location || '').slice(0, 100),
        row: String(req.body.context && req.body.context.row || '').slice(0, 100),
        rack: String(req.body.context && req.body.context.rack || '').slice(0, 100)
      })
    ].join('\n');

    let endpoint = baseUrl.replace(/\/+$/, '');
    if (!/\/chat\/completions$/i.test(endpoint)) endpoint += '/chat/completions';

    const requestBody = JSON.stringify({
      model: process.env.KIMI_MODEL || process.env.AI_MODEL || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 2048,
      messages: [{ role: 'system', content: system }, ...messages]
    });

    let result;
    try {
      result = await kimiRequest(endpoint, requestBody, process.env.KIMI_CA_CERT_PATH, process.env.KIMI_API_KEY || process.env.AI_API_KEY);
    } catch (e) {
      console.error('[ai] upstream connection failed:', e.message);
      const fallback = local.handled ? local.answer : 'The AI service could not be reached. Please try again later.';
      return res.status(502).json({ error: 'The AI service could not be reached.', answer: fallback });
    }

    const payload = result.payload;
    if (result.status < 200 || result.status >= 300) {
      console.error('[ai] upstream request failed:', result.status, payload.error || payload);
      const fallback = local.handled ? local.answer : 'The AI service could not answer right now.';
      return res.status(502).json({ error: 'The AI service could not answer right now.', answer: fallback });
    }

    const responseMessage = payload.choices && payload.choices[0] && payload.choices[0].message;
    let answer = responseMessage && responseMessage.content;

    // Fallback if LLM returns garbage
    if (typeof answer !== 'string' || !answer.trim() || answer.length < 3) {
      console.error('[ai] upstream returned no/empty assistant message');
      if (local.handled) return res.json({ answer: local.answer });
      return res.status(502).json({ error: 'The AI service returned an empty answer.' });
    }

    // If the model tried to use a tool (text-based), we could parse it here.
    // For now, just return the answer. If the answer is too generic, fall back to local.
    if (local.handled && /check the ui|navigate|go to|click|page|exact keyword/i.test(answer)) {
      answer = local.answer + '\n\n(Assistant note: ' + answer.trim() + ')';
    }

    res.json({ answer: answer.trim() });
  }));

  /* --- Farm intrusion monitor --- */
  const farmText = (value, max = 200) => String(value ?? '').trim().slice(0, max);
  const farmId = () => 'farm_' + newId();
  const farmNumber = (value, fallback = 0) => {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  };
  const queueDeterrent = async ({ zoneId = '', eventId = '', by }) => {
    const zone = zoneId ? await db.get('SELECT * FROM farm_zones WHERE id=?', [zoneId]) : null;
    if (!zone || !Number(zone.deterrent_enabled)) return null;
    const cooldown = Math.max(30, Math.min(86400, Number(zone.cooldown_seconds) || 300));
    const lastAction = await db.get('SELECT id,requested_at FROM farm_deterrent_actions WHERE zone_id=? ORDER BY requested_at DESC LIMIT 1', [zoneId]);
    const recent = lastAction && (Date.now() - new Date(lastAction.requested_at).getTime() < cooldown * 1000) ? lastAction : null;
    if (recent) return null;
    const frequency = farmText((await db.get("SELECT value FROM farm_settings WHERE key='deterrent_frequency'", []))?.value || 'configured-device-profile', 80);
    const duration = Math.max(1, Math.min(60, Number((await db.get("SELECT value FROM farm_settings WHERE key='deterrent_duration_seconds'", []))?.value || 10)));
    const id = farmId();
    await db.run(
      'INSERT INTO farm_deterrent_actions(id,zone_id,event_id,mode,frequency,duration_seconds,result,requested_by) VALUES(?,?,?,?,?,?,?,?)',
      [id, zoneId, eventId, 'automatic', frequency, duration, 'queued', by]
    );
    return { id, mode: 'automatic', result: 'queued', frequency, duration_seconds: duration };
  };
  app.get('/farm-monitor', (req, res) => res.sendFile(path.join(__dirname, 'public', 'farm-monitor.html')));
  app.get('/api/farm/dashboard', auth, wrap(async (req, res) => {
    const [events, cameras, zones, readings, actions] = await Promise.all([
      db.all("SELECT * FROM farm_events ORDER BY detected_at DESC LIMIT 25"),
      db.all('SELECT id,name,stream_url,zone,enabled,last_seen FROM farm_cameras ORDER BY name'),
      db.all('SELECT * FROM farm_zones ORDER BY name'),
      db.all('SELECT * FROM farm_sensor_readings ORDER BY recorded_at DESC LIMIT 40'),
      db.all('SELECT * FROM farm_deterrent_actions ORDER BY requested_at DESC LIMIT 15'),
    ]);
    res.json({ events, cameras, zones, readings, actions });
  }));
  app.post('/api/farm/cameras', auth, need('admin', 'user'), wrap(async (req, res) => {
    const name = farmText(req.body.name, 100), streamUrl = farmText(req.body.stream_url, 1000), zone = farmText(req.body.zone, 100);
    if (!name || !streamUrl) return res.status(400).json({ error: 'Camera name and RTSP/HLS stream URL are required.' });
    const id = farmId();
    await db.run('INSERT INTO farm_cameras(id,name,stream_url,zone,created_by) VALUES(?,?,?,?,?)', [id, name, streamUrl, zone, req.user.username]);
    res.status(201).json({ id, name, stream_url: streamUrl, zone, enabled: 1 });
  }));
  app.patch('/api/farm/cameras/:id', auth, need('admin', 'user'), wrap(async (req, res) => {
    const camera = await db.get('SELECT id FROM farm_cameras WHERE id=?', [req.params.id]);
    if (!camera) return res.status(404).json({ error: 'Camera not found.' });
    const fields = [], values = [];
    if (req.body.name !== undefined) { fields.push('name=?'); values.push(farmText(req.body.name, 100)); }
    if (req.body.stream_url !== undefined) { fields.push('stream_url=?'); values.push(farmText(req.body.stream_url, 1000)); }
    if (req.body.zone !== undefined) { fields.push('zone=?'); values.push(farmText(req.body.zone, 100)); }
    if (req.body.enabled !== undefined) { fields.push('enabled=?'); values.push(req.body.enabled ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ error: 'No camera changes supplied.' });
    values.push(req.params.id); await db.run(`UPDATE farm_cameras SET ${fields.join(',')} WHERE id=?`, values);
    res.json({ ok: true });
  }));
  app.post('/api/farm/zones', auth, need('admin', 'user'), wrap(async (req, res) => {
    const name = farmText(req.body.name, 100);
    if (!name) return res.status(400).json({ error: 'Zone name is required.' });
    const id = farmId(), cooldown = Math.max(30, Math.min(86400, Math.round(farmNumber(req.body.cooldown_seconds, 300))));
    await db.run('INSERT INTO farm_zones(id,name,crop,deterrent_enabled,cooldown_seconds,created_by) VALUES(?,?,?,?,?,?)',
      [id, name, farmText(req.body.crop, 100), req.body.deterrent_enabled ? 1 : 0, cooldown, req.user.username]);
    res.status(201).json({ id, name, cooldown_seconds: cooldown });
  }));
  app.patch('/api/farm/zones/:id', auth, need('admin', 'user'), wrap(async (req, res) => {
    const zone = await db.get('SELECT id FROM farm_zones WHERE id=?', [req.params.id]);
    if (!zone) return res.status(404).json({ error: 'Zone not found.' });
    const fields = [], values = [];
    if (req.body.deterrent_enabled !== undefined) { fields.push('deterrent_enabled=?'); values.push(req.body.deterrent_enabled ? 1 : 0); }
    if (req.body.cooldown_seconds !== undefined) { fields.push('cooldown_seconds=?'); values.push(Math.max(30, Math.min(86400, Math.round(farmNumber(req.body.cooldown_seconds, 300))))); }
    if (req.body.crop !== undefined) { fields.push('crop=?'); values.push(farmText(req.body.crop, 100)); }
    if (!fields.length) return res.status(400).json({ error: 'No zone changes supplied.' });
    values.push(req.params.id); await db.run(`UPDATE farm_zones SET ${fields.join(',')} WHERE id=?`, values); res.json({ ok: true });
  }));
  app.post('/api/farm/events', auth, need('admin', 'user'), wrap(async (req, res) => {
    const id = farmId(), animal = farmText(req.body.animal || 'Unknown', 80), zoneId = farmText(req.body.zone_id, 100);
    const confidence = Math.max(0, Math.min(1, farmNumber(req.body.confidence, 0)));
    const severity = ['low', 'medium', 'high', 'critical'].includes(req.body.severity) ? req.body.severity : 'medium';
    await db.run('INSERT INTO farm_events(id,camera_id,zone_id,animal,confidence,severity,snapshot_url,created_by) VALUES(?,?,?,?,?,?,?,?)',
      [id, farmText(req.body.camera_id, 100), zoneId, animal, confidence, severity, farmText(req.body.snapshot_url, 1000), req.user.username]);
    const deterrent = await queueDeterrent({ zoneId, eventId: id, by: req.user.username });
    res.status(201).json({ id, deterrent });
  }));
  app.post('/api/farm/sensors', auth, need('admin', 'user'), wrap(async (req, res) => {
    const rows = Array.isArray(req.body.readings) ? req.body.readings : [req.body];
    if (!rows.length || rows.length > 500) return res.status(400).json({ error: 'Send between 1 and 500 sensor readings.' });
    for (const row of rows) {
      const deviceId = farmText(row.device_id, 100), metric = farmText(row.metric, 80);
      if (!deviceId || !metric || !Number.isFinite(Number(row.value))) return res.status(400).json({ error: 'Each reading needs device_id, metric and numeric value.' });
      await db.run('INSERT INTO farm_sensor_readings(id,device_id,zone_id,metric,value,unit) VALUES(?,?,?,?,?,?)',
        [farmId(), deviceId, farmText(row.zone_id, 100), metric, Number(row.value), farmText(row.unit, 30)]);
    }
    res.status(201).json({ accepted: rows.length });
  }));
  app.post('/api/farm/deterrent/test', auth, need('admin', 'user'), wrap(async (req, res) => {
    const duration = Math.max(1, Math.min(60, Math.round(farmNumber(req.body.duration_seconds, 5))));
    const frequency = farmText(req.body.frequency || 'configured-device-profile', 80);
    const id = farmId();
    await db.run('INSERT INTO farm_deterrent_actions(id,zone_id,event_id,mode,frequency,duration_seconds,result,requested_by) VALUES(?,?,?,?,?,?,?,?)',
      [id, farmText(req.body.zone_id, 100), '', 'manual-test', frequency, duration, 'queued', req.user.username]);
    res.status(201).json({ id, result: 'queued', warning: 'Hardware gateway integration is not configured; this action is recorded only.' });
  }));
  app.put('/api/farm/settings', auth, need('admin'), wrap(async (req, res) => {
    const entries = { deterrent_frequency: farmText(req.body.deterrent_frequency, 80), deterrent_duration_seconds: String(Math.max(1, Math.min(60, Math.round(farmNumber(req.body.deterrent_duration_seconds, 10))))) };
    for (const [key, value] of Object.entries(entries)) {
      await db.run('INSERT INTO farm_settings(key,value,updated_by) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP', [key, value, req.user.username]);
    }
    res.json({ ok: true });
  }));

  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  /* ---------- Start (HTTP, or HTTPS when a certificate is configured) ---------- */
  const sslOpts = (() => {
    const rd = f => fs.readFileSync(path.resolve(__dirname, f));
    if (process.env.SSL_PFX_FILE) return { pfx: rd(process.env.SSL_PFX_FILE), passphrase: process.env.SSL_PFX_PASSPHRASE || undefined };
    if (process.env.SSL_CERT_FILE && process.env.SSL_KEY_FILE) return { cert: rd(process.env.SSL_CERT_FILE), key: rd(process.env.SSL_KEY_FILE) };
    return null;
  })();
  const onUp = () => {
    console.log(`DC Inventory running on ${sslOpts ? 'https' : 'http'}://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    console.log(`Database: ${db.kind === 'sqlite' ? 'SQLite file ' : ''}${db.label}`);
    if (!sslOpts) console.log('Note: plain HTTP. Set SSL_PFX_FILE (or SSL_CERT_FILE + SSL_KEY_FILE) in .env to enable HTTPS.');
  };
  (sslOpts ? require('https').createServer(sslOpts, app) : require('http').createServer(app)).listen(PORT, HOST, onUp);
}
main().catch(e => {
  console.error('Startup failed:', e.message);
  if (process.env.DATABASE_URL) console.error('Check DATABASE_URL in .env (host, port, user, password, SSL and the database firewall), or leave it empty to use the local SQLite file.');
  process.exit(1);
});