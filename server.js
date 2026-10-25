'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32 || !process.env.ADMIN_API_KEY || process.env.ADMIN_API_KEY.length < 24) {
  console.error('Set JWT_SECRET (32+ chars) and ADMIN_API_KEY (24+ chars) environment variables.'); process.exit(1);
}
const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 referral_code TEXT NOT NULL UNIQUE,
 referred_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 status TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by);
`);
const findByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findByCode = db.prepare('SELECT * FROM users WHERE referral_code = ?');
const countRefs = db.prepare("SELECT COUNT(*) AS n FROM users WHERE referred_by = ? AND status = 'active'");
function cleanEmail(v) { return String(v || '').trim().toLowerCase(); }
function referralCode() { return crypto.randomBytes(5).toString('hex').toUpperCase(); }
function issueToken(user) { return jwt.sign({ sub: String(user.id) }, process.env.JWT_SECRET, { expiresIn: '7d', issuer: 'future-ai-demo' }); }
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, referralCode: u.referral_code, createdAt: u.created_at }; }
function auth(req, res, next) {
 const header = req.get('authorization') || ''; const token = header.startsWith('Bearer ') ? header.slice(7) : '';
 try { const payload = jwt.verify(token, process.env.JWT_SECRET, { issuer: 'future-ai-demo' }); req.userId = Number(payload.sub); next(); }
 catch { return res.status(401).json({ error: 'يرجى تسجيل الدخول من جديد.' }); }
}
app.get('/api/health', (_req,res) => res.json({ status: 'ok', mode: 'demo-no-financial-transactions' }));
app.post('/api/register', async (req,res) => {
 try {
  const name = String(req.body.name || '').trim(); const email = cleanEmail(req.body.email); const password = String(req.body.password || ''); const code = String(req.body.referralCode || '').trim().toUpperCase();
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: 'أدخل اسمًا صحيحًا (2 إلى 80 حرفًا).' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 190) return res.status(400).json({ error: 'البريد الإلكتروني غير صحيح.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل.' });
  if (findByEmail.get(email)) return res.status(409).json({ error: 'هذا البريد مسجل مسبقًا.' });
  let referrer = null;
  if (code) { referrer = findByCode.get(code); if (!referrer) return res.status(400).json({ error: 'كود الدعوة غير صحيح.' }); }
  let rc; do { rc = referralCode(); } while (findByCode.get(rc));
  const hash = await bcrypt.hash(password, 12);
  const insert = db.prepare('INSERT INTO users (name,email,password_hash,referral_code,referred_by) VALUES (?,?,?,?,?)');
  const result = insert.run(name,email,hash,rc,referrer ? referrer.id : null);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
  res.status(201).json({ token: issueToken(user), user: publicUser(user), message: 'تم إنشاء الحساب. مكافآت الدعوات ليست مفعلة للدفع في هذه النسخة.' });
 } catch (e) { console.error(e); res.status(500).json({ error: 'تعذر إنشاء الحساب حاليًا.' }); }
});
app.post('/api/login', async (req,res) => {
 const email = cleanEmail(req.body.email); const password = String(req.body.password || '');
 const user = findByEmail.get(email);
 if (!user || user.status !== 'active' || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({ error: 'البريد أو كلمة المرور غير صحيحة.' });
 res.json({ token: issueToken(user), user: publicUser(user) });
});
app.get('/api/me', auth, (req,res) => {
 const user = db.prepare("SELECT * FROM users WHERE id=? AND status='active'").get(req.userId);
 if (!user) return res.status(401).json({ error: 'الحساب غير موجود أو غير نشط.' });
 const referralCount = countRefs.get(user.id).n;
 res.json({ user: publicUser(user), referralCount, referralGoal: 10, proposedRewardDA: referralCount >= 10 ? 5000 : null, rewardStatus: 'not_enabled_no_payment', notice: 'الوصول إلى 10 دعوات لا ينشئ رصيدًا ماليًا أو حقًا بالدفع تلقائيًا؛ المكافأة غير مفعّلة في النسخة التجريبية.' });
});
app.get('/api/referrals', auth, (req,res) => {
 const rows = db.prepare("SELECT name, created_at FROM users WHERE referred_by=? AND status='active' ORDER BY id DESC LIMIT 100").all(req.userId);
 res.json({ referrals: rows, count: countRefs.get(req.userId).n, goal: 10, rewardEnabled: false });
});
app.get('/api/admin/users', (req,res) => {
 if (!safeEqual(req.get('x-admin-key') || '', process.env.ADMIN_API_KEY)) return res.status(403).json({ error: 'غير مصرح.' });
 const rows = db.prepare(`SELECT u.id,u.name,u.email,u.referral_code,u.created_at,u.status,
 (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.id AND r.status='active') AS referral_count
 FROM users u ORDER BY u.id DESC LIMIT 500`).all();
 res.json({ users: rows, total: db.prepare('SELECT COUNT(*) AS n FROM users').get().n });
});
function safeEqual(a,b) { const aa=Buffer.from(a); const bb=Buffer.from(b); return aa.length===bb.length && crypto.timingSafeEqual(aa,bb); }
app.use(express.static(path.join(__dirname,'public')));
app.use((err,_req,res,_next) => { console.error(err); res.status(500).json({ error: 'خطأ داخلي.' }); });
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Future AI demo server listening on http://localhost:${port}`));
