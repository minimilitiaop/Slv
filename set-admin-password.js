'use strict';
// Usage: node set-admin-password.js "your new long password"
// Run while the server is STOPPED, then start it again.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const pw = process.argv[2];
if (!pw || pw.length < 10) { console.error('Provide a password of at least 10 characters:\n  node set-admin-password.js "my long password"'); process.exit(1); }
const file = path.join(__dirname, 'data', 'db.json');
if (!fs.existsSync(file)) { console.error('Start the server once first (it creates data/db.json), or set ADMIN_PASSWORD before starting the server.'); process.exit(1); }
const db = JSON.parse(fs.readFileSync(file, 'utf8'));
const s = crypto.randomBytes(16);
db.admin = { s: s.toString('hex'), h: crypto.scryptSync(pw, s, 64).toString('hex') };
fs.writeFileSync(file, JSON.stringify(db));
console.log('Admin password updated.');
