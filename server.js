const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// --- CORS: only your static site is allowed to call this API ---
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// --- Database ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS entries (
      id SERIAL PRIMARY KEY,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      download_url TEXT NOT NULL,
      lines BIGINT,
      size_bytes BIGINT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
}
ensureTable().catch(err => console.error('Table init failed:', err));

// --- Simple signed-cookie session (no extra services needed) ---
const SECRET = process.env.SESSION_SECRET || 'please-set-SESSION_SECRET';
function sign(payload) {
  const h = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return `${payload}.${h}`;
}
function verify(token) {
  if (!token) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  if (expected !== sig) return false;
  return Number(payload) > Date.now();
}
function requireAuth(req, res, next) {
  if (verify(req.cookies.session)) return next();
  res.status(401).json({ error: 'unauthorized' });
}

// --- Auth routes ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const okUser = username === process.env.ADMIN_USER;
  const okPass = password === process.env.ADMIN_PASSWORD;
  if (okUser && okPass) {
    const expiry = Date.now() + 1000 * 60 * 60 * 24 * 30; // 30 days
    res.cookie('session', sign(String(expiry)), {
      httpOnly: true, sameSite: 'none', secure: true, maxAge: 1000 * 60 * 60 * 24 * 30
    });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  res.json({ authenticated: verify(req.cookies.session) });
});

// --- Entries routes ---
app.get('/api/entries', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, category, title, download_url AS "downloadUrl", lines,
            size_bytes AS "sizeBytes", created_at AS "createdAt"
     FROM entries ORDER BY created_at DESC`
  );
  res.json(rows);
});

app.post('/api/entries', requireAuth, async (req, res) => {
  const { category, title, downloadUrl, lines, sizeBytes } = req.body || {};
  if (!category || !title || !downloadUrl) {
    return res.status(400).json({ error: 'missing fields' });
  }
  const { rows } = await pool.query(
    `INSERT INTO entries (category, title, download_url, lines, size_bytes)
     VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [category, title, downloadUrl, lines ?? null, sizeBytes ?? null]
  );
  res.json({ id: rows[0].id });
});

app.delete('/api/entries/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM entries WHERE ? id=$1', [req.params.id]);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('API listening on port', PORT));
