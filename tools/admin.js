'use strict';
// Account helper — run from the project folder (works for SQLite and PostgreSQL, same settings as the server):
//   npm run users -- list
//   npm run users -- reset <username> <new-password>
//   npm run users -- create <username> <password> [admin|user|viewer]
//   npm run users -- role <username> <admin|user|viewer>
//   npm run users -- delete <username>
const path = require('path'), fs = require('fs'), crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });
const { connect } = require('../db');
const [cmd, user, arg3, arg4] = process.argv.slice(2);
const hashPw = pw => { const salt = crypto.randomBytes(16).toString('hex'); return [salt, crypto.scryptSync(pw, salt, 64).toString('hex')]; };
const ROLES = ['admin', 'user', 'viewer'];
(async () => {
  const file = path.join(path.resolve(__dirname, '..', process.env.DATA_DIR || 'data'), 'inventory.db');
  if (!process.env.DATABASE_URL && !fs.existsSync(file)) { console.log('No database yet at ' + file + '\nStart the server once (npm start) so it is created.'); return; }
  const db = await connect(process.env.DATABASE_URL ? { url: process.env.DATABASE_URL } : { file });
  const exists = async u => db.get('SELECT 1 AS x FROM users WHERE username=?', [u]);
  if (cmd === 'list') {
    console.log('Database: ' + db.label);
    const rows = await db.all('SELECT username, role, created_at FROM users ORDER BY username');
    console.log(rows.length ? rows.map(r => ` ${r.username.padEnd(20)} ${r.role.padEnd(8)} created ${r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at}`).join('\n') : ' (no users yet — the first visit to the site creates the administrator)');
    console.log('\nPasswords are stored as one-way hashes and cannot be shown. Use "reset" to set a new one.');
  } else if (cmd === 'reset' && user && arg3) {
    if (arg3.length < 8) console.log('Password must be at least 8 characters.');
    else if (!(await exists(user.toLowerCase()))) console.log('No such user: ' + user + '. Run "list" to see usernames.');
    else { const [s, h] = hashPw(arg3); await db.run('UPDATE users SET salt=?, hash=? WHERE username=?', [s, h, user.toLowerCase()]); console.log('Password reset for ' + user.toLowerCase()); }
  } else if (cmd === 'create' && user && arg3) {
    const role = arg4 || 'admin', u = user.toLowerCase();
    if (!ROLES.includes(role) || arg3.length < 8 || !/^[a-z0-9._-]{2,40}$/.test(u)) console.log('Need: username (2-40 chars a-z 0-9 . _ -), password (8+ chars), role admin|user|viewer');
    else if (await exists(u)) console.log('User already exists. Use "reset" instead.');
    else { const [s, h] = hashPw(arg3); await db.run('INSERT INTO users(username,salt,hash,role) VALUES(?,?,?,?)', [u, s, h, role]); console.log('Created ' + role + ' account: ' + u); }
  } else if (cmd === 'role' && user && ROLES.includes(arg3)) {
    console.log((await db.run('UPDATE users SET role=? WHERE username=?', [arg3, user.toLowerCase()])) ? 'Role updated.' : 'No such user.');
  } else if (cmd === 'delete' && user) {
    console.log((await db.run('DELETE FROM users WHERE username=?', [user.toLowerCase()])) ? 'User deleted.' : 'No such user.');
  } else console.log('Usage:\n  npm run users -- list\n  npm run users -- reset <username> <new-password>\n  npm run users -- create <username> <password> [admin|user|viewer]\n  npm run users -- role <username> <admin|user|viewer>\n  npm run users -- delete <username>');
  await db.close();
})().catch(e => { console.error('Error:', e.message); process.exit(1); });
