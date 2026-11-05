'use strict';
// Copies all users and inventory from the local SQLite file into the PostgreSQL database in DATABASE_URL.
// Safe to re-run: rows that already exist are skipped. Stop the server first.
//   npm run migrate
const path = require('path'), fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });
const { connect, FIELDS, q } = require('../db');
(async () => {
  if (!process.env.DATABASE_URL) { console.log('Set DATABASE_URL in .env first (your PostgreSQL connection string).'); process.exit(1); }
  const file = path.join(path.resolve(__dirname, '..', process.env.DATA_DIR || 'data'), 'inventory.db');
  if (!fs.existsSync(file)) { console.log('No local SQLite database found at ' + file); process.exit(1); }
  const src = await connect({ file }), dst = await connect({ url: process.env.DATABASE_URL });
  const users = await src.all('SELECT username,salt,hash,role,created_at FROM users');
  const items = await src.all(`SELECT id,${FIELDS.map(q).join(',')},updated_by,updated_at FROM items`);
  const uCols = 'username,salt,hash,role,created_at', iCols = ['id', ...FIELDS.map(q), 'updated_by', 'updated_at'].join(',');
  await dst.tx(async t => {
    for (const u of users) await t.run(`INSERT INTO users(${uCols}) VALUES(?,?,?,?,?) ON CONFLICT(username) DO NOTHING`, [u.username, u.salt, u.hash, u.role, u.created_at]);
    for (const i of items) await t.run(`INSERT INTO items(${iCols}) VALUES(${Array(FIELDS.length + 3).fill('?').join(',')}) ON CONFLICT(id) DO NOTHING`,
      [i.id, ...FIELDS.map(f => i[f]), i.updated_by, i.updated_at]);
  });
  const n = async tb => Number((await dst.get(`SELECT COUNT(*) AS n FROM ${tb}`)).n);
  console.log(`Copied from ${file}\n  users in PostgreSQL: ${await n('users')} (source ${users.length})\n  items in PostgreSQL: ${await n('items')} (source ${items.length})`);
  await src.close(); await dst.close();
})().catch(e => { console.error('Migration failed:', e.message); process.exit(1); });
