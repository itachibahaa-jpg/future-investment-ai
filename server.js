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
app.use(express.json({ limit: '3mb' }));
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

CREATE TABLE IF NOT EXISTS package_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 package_name TEXT NOT NULL,
 package_price INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'inquiry_received',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_package_requests_user_id ON package_requests(user_id);

CREATE TABLE IF NOT EXISTS payment_submissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 package_name TEXT NOT NULL,
 package_price INTEGER NOT NULL,
 payment_method TEXT NOT NULL,
 receipt_data TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_subscriptions (
 user_id INTEGER PRIMARY KEY REFERENCES users(id),
 package_name TEXT NOT NULL,
 package_price INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'active',
 activated_at TEXT NOT NULL DEFAULT (datetime('now')),
 payment_submission_id INTEGER NOT NULL UNIQUE REFERENCES payment_submissions(id)
);
CREATE TABLE IF NOT EXISTS daily_wheel_spins (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 spin_date TEXT NOT NULL DEFAULT (date('now')),
 prize_key TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 UNIQUE(user_id, spin_date)
);
CREATE TABLE IF NOT EXISTS deposit_wheel_spins (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 payment_submission_id INTEGER NOT NULL UNIQUE REFERENCES payment_submissions(id),
 prize_key TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_wheel_spins_user
ON daily_wheel_spins(user_id);`);

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
app.post('/api/wheel/spin', auth, (req, res) => {
  const prizes = [
    { key: 'bonus50', label: '50 ألف سنتيم مجانًا' },
    { key: 'referrals', label: 'دعوة 5 أشخاص للفوز بـ7 ملايين سنتيم' },
    { key: 'upgrade', label: 'فرصة ترقية الباقة' },
    { key: 'grand20m', label: 'الجائزة الكبرى: 20 مليون سنتيم' },
    { key: 'vip', label: 'ترقية مستوى VIP' }
  ];

  const prize = prizes[crypto.randomInt(prizes.length)];

  try {
    db.prepare(`
      INSERT INTO daily_wheel_spins (user_id, prize_key)
      VALUES (?, ?)
    `).run(req.userId, prize.key);

    res.json({
      success: true,
      prize: prize,
      financialRewardsEnabled: false,
      message: 'هذه نتيجة تجريبية. الجوائز المالية والترقيات غير مفعلة فعليًا.'
    });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'لقد استخدمت عجلة الحظ اليوم. حاول غدًا.'
      });
    }

    console.error(err);
    res.status(500).json({
      error: 'تعذر تدوير العجلة حاليًا.'
    });
  }
});
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
app.get('/api/me/subscription', auth, (req, res) => {
  const subscription = db.prepare(`
    SELECT package_name, package_price, status, activated_at
    FROM user_subscriptions
    WHERE user_id = ?
  `).get(req.userId);

  res.json({ subscription: subscription || null });
});
app.get('/api/referrals', auth, (req,res) => {
 const rows = db.prepare("SELECT name, created_at FROM users WHERE referred_by=? AND status='active' ORDER BY id DESC LIMIT 100").all(req.userId);
 res.json({ referrals: rows, count: countRefs.get(req.userId).n, goal: 10, rewardEnabled: false });
});
app.post('/api/package-requests', auth, (req, res) => {
  const allowedPackages = {
    'الباقة البرونزية': 5000,
    'الباقة الفضية': 7000,
    'الباقة الذهبية': 10000,
    'الباقة الماسية': 20000,
    'الباقة الماسية المميزة': 50000,
    'باقة VIP': 70000,
    'باقة VIP Premium': 100000
  };

  const { package_name } = req.body || {};
  const package_price = allowedPackages[package_name];

  if (!package_price) {
    return res.status(400).json({ error: 'الباقة غير صحيحة.' });
  }

  try {
    const result = db.prepare(
      'INSERT INTO package_requests (user_id, package_name, package_price) VALUES (?, ?, ?)'
    ).run(req.userId, package_name, package_price);

    res.status(201).json({
      success: true,
      message: 'تم تسجيل طلب الاستفسار عن الباقة بنجاح. هذا الطلب ليس عملية دفع أو تفعيل.',
      requestId: Number(result.lastInsertRowid)
    });
  } catch (error) {
        console.error('Package request error:', error.message);
    res.status(500).json({ error: 'تعذر تسجيل الطلب حاليًا.' });
  }
});
app.post('/api/payment-submissions', auth, (req, res) => {
  const { package_name, payment_method, receipt_data } = req.body || {};

  const prices = {
    'الباقة البرونزية': 5000,
    'الباقة الفضية': 7000,
    'الباقة الذهبية': 10000,
    'الباقة الماسية': 20000,
    'الباقة الماسية المميزة': 50000,
    'باقة VIP': 70000,
    'باقة VIP Premium': 100000
  };

 const isGeneralDeposit = !package_name;

if (!isGeneralDeposit && !prices[package_name]) {
  return res.status(400).json({ error: 'الباقة غير صحيحة.' });
}

  if (!['BaridiMob', 'CCP'].includes(payment_method)) {
    return res.status(400).json({ error: 'طريقة الدفع غير صحيحة.' });
  }

  if (
    typeof receipt_data !== 'string' ||
    !/^data:image\/(png|jpeg|webp);base64,/.test(receipt_data) ||
    receipt_data.length > 2800000
  ) {
    return res.status(400).json({ error: 'صورة الوصل غير صحيحة أو كبيرة.' });
  }

  const result = db.prepare(`
    INSERT INTO payment_submissions
    (user_id, package_name, package_price, payment_method, receipt_data)
        VALUES (?, ?, ?, ?, ?)
  `).run(
    req.userId,
    package_name || 'إيداع عام',
    package_name ? prices[package_name] : 0,
    payment_method,
    receipt_data
  );

res.status(201).json({
  success: true,
  status: 'pending',
  submissionId: Number(result.lastInsertRowid),
  message: 'تم استلام الوصل، والطلب قيد المراجعة.'
});
});
app.get('/api/admin/users', (req,res) => {
  if (!safeEqual(req.get('x-admin-key') || '', process.env.ADMIN_API_KEY)) return res.status(403).json({ error: 'غير مصرح.' });
 const rows = db.prepare(`SELECT u.id,u.name,u.email,u.referral_code,u.created_at,u.status,
 (SELECT COUNT(*) FROM users r WHERE r.referred_by=u.id AND r.status='active') AS referral_count
 FROM users u ORDER BY u.id DESC LIMIT 500`).all();
 res.json({ users: rows, total: db.prepare('SELECT COUNT(*) AS n FROM users').get().n });
});
app.get('/api/admin/payment-submissions', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!process.env.ADMIN_API_KEY ||
      !safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  try {
    const rows = db.prepare(`
      SELECT p.id, p.user_id, u.name AS user_name,
             u.email, p.package_name, p.package_price,
             p.payment_method, p.receipt_data,
             p.status, p.created_at
      FROM payment_submissions p
      LEFT JOIN users u ON u.id = p.user_id
      ORDER BY p.id DESC
      LIMIT 100
    `).all();

    res.json({ submissions: rows });
  } catch (error) {
    res.status(500).json({ error: 'تعذر جلب طلبات الدفع.' });
  }
});
app.patch('/api/admin/payment-submissions/:id', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (
    !process.env.ADMIN_API_KEY ||
    !safeEqual(key, process.env.ADMIN_API_KEY)
  ) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  const id = Number(req.params.id);
  const status = req.body?.status;

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: 'رقم الطلب غير صحيح.' });
  }

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({
      error: 'الحالة يجب أن تكون approved أو rejected.'
    });
  }

  try {
    const processRequest = db.transaction(() => {
      const submission = db.prepare(
        'SELECT * FROM payment_submissions WHERE id = ?'
      ).get(id);

      if (!submission) {
        return { error: 'الطلب غير موجود.', code: 404 };
      }

      if (submission.status !== 'pending') {
        return {
          error: 'تمت معالجة هذا الطلب مسبقًا.',
          code: 409
        };
      }
if (
  status === 'approved' &&
  submission.package_name === 'إيداع عام'
) {
  return {
    error: 'لا يمكن تفعيل اشتراك من إيداع عام دون اختيار باقة.',
    code: 400
  };
}
      if (status === 'approved') {
        db.prepare(`
          INSERT INTO user_subscriptions
            (user_id, package_name, package_price, status,
             activated_at, payment_submission_id)
          VALUES (?, ?, ?, 'active', datetime('now'), ?)
          ON CONFLICT(user_id) DO UPDATE SET
            package_name = excluded.package_name,
            package_price = excluded.package_price,
            status = 'active',
            activated_at = datetime('now'),
            payment_submission_id = excluded.payment_submission_id
        `).run(
          submission.user_id,
          submission.package_name,
          submission.package_price,
          submission.id
        );
      }

      db.prepare(
        'UPDATE payment_submissions SET status = ? WHERE id = ?'
      ).run(status, id);

      return {
        success: true,
        status,
        message: status === 'approved'
          ? 'تم قبول الطلب وتفعيل الاشتراك.'
          : 'تم رفض الطلب.'
      };
    });

    const result = processRequest();

    if (result.error) {
      return res.status(result.code).json({
        error: result.error
      });
    }

    return res.json(result);
  } catch (error) {
    console.error('Payment review error:', error.message);
    return res.status(500).json({
      error: 'تعذرت معالجة الطلب.'
    });
  }
});
function safeEqual(a,b) { const aa=Buffer.from(a); const bb=Buffer.from(b); return aa.length===bb.length && crypto.timingSafeEqual(aa,bb); }
// Update account name
app.patch('/api/me/profile', auth, (req, res) => {
  const name = String(req.body.name || '').trim();

  if (name.length < 2 || name.length > 80) {
    return res.status(400).json({
      error: 'الاسم يجب أن يكون بين حرفين و80 حرفًا.'
    });
  }

  const result = db.prepare(
    "UPDATE users SET name = ? WHERE id = ? AND status = 'active'"
  ).run(name, req.userId);

  if (!result.changes) {
    return res.status(404).json({ error: 'الحساب غير موجود أو غير نشط.' });
  }

  const user = db.prepare(
    'SELECT * FROM users WHERE id = ?'
  ).get(req.userId);

  res.json({
    message: 'تم تحديث الاسم بنجاح.',
    user: publicUser(user)
  });
});

// Change password
app.post('/api/me/change-password', auth, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '');

    if (newPassword.length < 8 || newPassword.length > 128) {
      return res.status(400).json({
        error: 'كلمة المرور الجديدة يجب أن تكون بين 8 و128 حرفًا.'
      });
    }

    const user = db.prepare(
      "SELECT * FROM users WHERE id = ? AND status = 'active'"
    ).get(req.userId);

    if (!user) {
      return res.status(404).json({ error: 'الحساب غير موجود أو غير نشط.' });
    }

    const valid = await bcrypt.compare(
      currentPassword,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'كلمة المرور الحالية غير صحيحة.'
      });
    }

    const hash = await bcrypt.hash(newPassword, 12);

    db.prepare(
      'UPDATE users SET password_hash = ? WHERE id = ?'
    ).run(hash, req.userId);

    res.json({ message: 'تم تغيير كلمة المرور بنجاح.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'تعذر تغيير كلمة المرور حاليًا.'
    });
  }
});
app.use(express.static(path.join(__dirname,'public')));
app.use((err,_req,res,_next) => { console.error(err); res.status(500).json({ error: 'خطأ داخلي.' }); });
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Future AI demo server listening on http://localhost:${port}`));
