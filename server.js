const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1); // Render est derrière un proxy
app.use(express.json());
app.use(cookieParser());

// --- CORS (optionnel) ---
// Inutile si la page est servie par ce serveur (même domaine).
// Si tu héberges le HTML ailleurs, mets ALLOWED_ORIGIN="https://monsite.com" (plusieurs séparés par des virgules).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '')
  .split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- Base de données ---
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

// --- Session par cookie signé ---
const SECRET = process.env.SESSION_SECRET || 'please-set-SESSION_SECRET';
const SESSION_MS = 1000 * 60 * 60 * 24 * 30; // 30 jours

function sign(payload) {
  const h = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return `${payload}.${h}`;
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function verify(token) {
  if (!token) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  if (!safeEqual(expected, sig)) return false;
  return Number(payload) > Date.now();
}
function requireAuth(req, res, next) {
  if (verify(req.cookies.session)) return next();
  res.status(401).json({ error: 'unauthorized' });
}

// Si la page est sur un autre domaine il faut SameSite=None, sinon Lax suffit.
const crossSite = ALLOWED_ORIGINS.length > 0;
const cookieOpts = {
  httpOnly: true,
  secure: true,
  sameSite: crossSite ? 'none' : 'lax',
  maxAge: SESSION_MS
};

// --- Routes auth ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const okUser = process.env.ADMIN_USER && safeEqual(username ?? '', process.env.ADMIN_USER);
  const okPass = process.env.ADMIN_PASSWORD && safeEqual(password ?? '', process.env.ADMIN_PASSWORD);
  if (okUser && okPass) {
    res.cookie('session', sign(String(Date.now() + SESSION_MS)), cookieOpts);
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session', { httpOnly: true, secure: true, sameSite: cookieOpts.sameSite });
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  res.json({ authenticated: verify(req.cookies.session) });
});

// --- Routes entries ---
app.get('/api/entries', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, category, title, download_url AS "downloadUrl", lines,
              size_bytes AS "sizeBytes", created_at AS "createdAt"
       FROM entries ORDER BY created_at DESC`
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/entries', requireAuth, async (req, res) => {
  try {
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
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.delete('/api/entries/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM entries WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

// --- Site statique (le HTML est dans /public) ---
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server listening on port', PORT));
