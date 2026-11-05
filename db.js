'use strict';
/* Database layer: SQLite file (default) or PostgreSQL (when DATABASE_URL is set). Same interface for both. */
const FIELDS = ['location','row','rack','u','model','serial','firmware','purpose','assetTag','owner','user','contract','remarks','ip','conn10g','item','status','pduA','pduB'];
const q = f => `"${f}"`;

function sqliteAdapter(file) {
  const { DatabaseSync } = require('node:sqlite');            // built into Node 22.13+
  const d = new DatabaseSync(file);
  d.exec('PRAGMA journal_mode = WAL');
  const mk = h => ({
    all: async (sql, p = []) => h.prepare(sql).all(...p),
    get: async (sql, p = []) => h.prepare(sql).get(...p),
    run: async (sql, p = []) => Number(h.prepare(sql).run(...p).changes),
  });
  return { kind: 'sqlite', label: file, ...mk(d), exec: async s => d.exec(s),
    tx: async fn => { d.exec('BEGIN'); try { const r = await fn(mk(d)); d.exec('COMMIT'); return r; } catch (e) { d.exec('ROLLBACK'); throw e; } },
    close: async () => d.close() };
}

function pgAdapter(url) {
  const { Pool } = require('pg');
  const ssl = process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== 'false' } : undefined;
  const pool = new Pool({ connectionString: url, ssl, max: parseInt(process.env.DATABASE_POOL, 10) || 10, connectionTimeoutMillis: 10000 });
  pool.on('error', e => console.error('[db] idle client error:', e.message));
  const conv = sql => { let i = 0; return sql.replace(/\?/g, () => '$' + (++i)); };   // ? placeholders -> $1, $2 ...
  const mk = h => ({
    all: async (sql, p = []) => (await h.query(conv(sql), p)).rows,
    get: async (sql, p = []) => (await h.query(conv(sql), p)).rows[0],
    run: async (sql, p = []) => (await h.query(conv(sql), p)).rowCount,
  });
  let label = 'PostgreSQL'; try { const u = new URL(url); label = `PostgreSQL ${u.hostname}:${u.port || 5432}${u.pathname}`; } catch {}
  return { kind: 'postgres', label, ...mk(pool), exec: async s => { await pool.query(s); },
    tx: async fn => { const c = await pool.connect(); try { await c.query('BEGIN'); const r = await fn(mk(c)); await c.query('COMMIT'); return r; } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); } },
    close: async () => pool.end() };
}

async function init(a) {
  const ts = a.kind === 'postgres' ? 'TIMESTAMPTZ' : 'TEXT';
  await a.exec(`CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','user','viewer')), created_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec(`CREATE TABLE IF NOT EXISTS items(
    id TEXT PRIMARY KEY, ${FIELDS.map(f => `${q(f)} TEXT NOT NULL DEFAULT ''`).join(', ')},
    updated_by TEXT, updated_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec('CREATE INDEX IF NOT EXISTS idx_items_place ON items(location, "row", rack)');
  await a.exec('CREATE INDEX IF NOT EXISTS idx_items_serial ON items(serial)');
  await a.exec(`CREATE TABLE IF NOT EXISTS farm_cameras(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, stream_url TEXT NOT NULL DEFAULT '',
    zone TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
    last_seen ${ts} DEFAULT CURRENT_TIMESTAMP, created_by TEXT NOT NULL,
    created_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec(`CREATE TABLE IF NOT EXISTS farm_zones(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, crop TEXT NOT NULL DEFAULT '',
    deterrent_enabled INTEGER NOT NULL DEFAULT 0, cooldown_seconds INTEGER NOT NULL DEFAULT 300,
    created_by TEXT NOT NULL, created_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec(`CREATE TABLE IF NOT EXISTS farm_events(
    id TEXT PRIMARY KEY, camera_id TEXT NOT NULL DEFAULT '', zone_id TEXT NOT NULL DEFAULT '',
    animal TEXT NOT NULL DEFAULT 'Unknown', confidence REAL NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'new',
    snapshot_url TEXT NOT NULL DEFAULT '', detected_at ${ts} DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL)`);
  await a.exec(`CREATE TABLE IF NOT EXISTS farm_sensor_readings(
    id TEXT PRIMARY KEY, device_id TEXT NOT NULL, zone_id TEXT NOT NULL DEFAULT '',
    metric TEXT NOT NULL, value REAL NOT NULL, unit TEXT NOT NULL DEFAULT '',
    recorded_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec(`CREATE TABLE IF NOT EXISTS farm_deterrent_actions(
    id TEXT PRIMARY KEY, zone_id TEXT NOT NULL DEFAULT '', event_id TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL, frequency TEXT NOT NULL DEFAULT '', duration_seconds INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT 'requested', requested_by TEXT NOT NULL,
    requested_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec(`CREATE TABLE IF NOT EXISTS farm_settings(
    key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_by TEXT NOT NULL,
    updated_at ${ts} DEFAULT CURRENT_TIMESTAMP)`);
  await a.exec('CREATE INDEX IF NOT EXISTS idx_farm_events_time ON farm_events(detected_at)');
  await a.exec('CREATE INDEX IF NOT EXISTS idx_farm_readings_time ON farm_sensor_readings(recorded_at)');
  return a;
}

/* connect({ url }) -> PostgreSQL;  connect({ file }) -> SQLite */
async function connect({ url, file }) { return init(url ? pgAdapter(url) : sqliteAdapter(file)); }
module.exports = { connect, FIELDS, q };
