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
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    error: 'محاولات كثيرة. يرجى الانتظار 15 دقيقة.'
  }
});
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new Database(dbPath);
const { Pool } = require('pg');
const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
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
CREATE TABLE IF NOT EXISTS support_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  sender TEXT NOT NULL CHECK(sender IN ('user', 'admin')),
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_support_messages_user
ON support_messages(user_id, id);
CREATE INDEX IF NOT EXISTS idx_wheel_spins_user
ON daily_wheel_spins(user_id);CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount REAL NOT NULL,
  method TEXT NOT NULL,
  payout_details TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending', 'rejected', 'completed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user
ON withdrawal_requests(user_id);

CREATE TABLE IF NOT EXISTS memory_game_daily (
  user_id INTEGER NOT NULL REFERENCES users(id),
  game_date TEXT NOT NULL,
  attempts_used INTEGER NOT NULL DEFAULT 0 CHECK(attempts_used BETWEEN 0 AND 2),
  PRIMARY KEY(user_id, game_date)
);

CREATE TABLE IF NOT EXISTS memory_game_attempts (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  game_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'started' CHECK(status IN ('started','won')),
  points_awarded INTEGER NOT NULL DEFAULT 0 CHECK(points_awarded IN (0,2)),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_memory_game_attempts_user
ON memory_game_attempts(user_id, game_date);

CREATE TABLE IF NOT EXISTS platform_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  review_text TEXT NOT NULL,
  rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending', 'approved', 'rejected')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_platform_reviews_status
ON platform_reviews(status, id);

CREATE TABLE IF NOT EXISTS balance_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  balance_type TEXT NOT NULL,
  amount REAL NOT NULL,
  payment_method TEXT NOT NULL
    CHECK(payment_method IN ('BaridiMob', 'CCP')),
  receipt_data TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending', 'approved', 'rejected')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_balance_requests_user
ON balance_requests(user_id, id);

CREATE INDEX IF NOT EXISTS idx_balance_requests_status
ON balance_requests(status, id);

`);
const balanceColumns = db.prepare(
  "PRAGMA table_info(balance_requests)"
).all().map(column => column.name);

if (!balanceColumns.includes("receiver_id")) {
  db.exec("ALTER TABLE balance_requests ADD COLUMN receiver_id TEXT");
}
if (!balanceColumns.includes("receiver_type")) {
  db.exec("ALTER TABLE balance_requests ADD COLUMN receiver_type TEXT");
}
if (!balanceColumns.includes("requested_quantity")) {
  db.exec("ALTER TABLE balance_requests ADD COLUMN requested_quantity REAL");
}
if (!balanceColumns.includes("custom_balance_name")) {
  db.exec("ALTER TABLE balance_requests ADD COLUMN custom_balance_name TEXT");
}
async function initializePersistentUsers() {
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      referral_code TEXT NOT NULL UNIQUE,
      referred_by BIGINT,
      created_at TEXT NOT NULL DEFAULT (NOW()::TEXT),
      status TEXT NOT NULL DEFAULT 'active'
    )
  `);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS platform_reviews (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      review_text TEXT NOT NULL,
      rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'approved', 'rejected')),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
    await pgPool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(120) NOT NULL,
      message VARCHAR(1000) NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pgPool.query(`
    CREATE INDEX IF NOT EXISTS idx_notifications_user
    ON notifications(user_id, id DESC)
  `);
    const oldReviews = db.prepare(
    'SELECT * FROM platform_reviews ORDER BY id'
  ).all();

  for (const review of oldReviews) {
    await pgPool.query(`
      INSERT INTO platform_reviews
      (id, name, review_text, rating, status, created_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (id) DO NOTHING
    `, [
      review.id,
      review.name,
      review.review_text,
      review.rating,
      review.status,
      review.created_at
    ]);
  }

  await pgPool.query(`
    SELECT setval(
      pg_get_serial_sequence('platform_reviews', 'id'),
      GREATEST(COALESCE((SELECT MAX(id) FROM platform_reviews), 1), 1),
      EXISTS(SELECT 1 FROM platform_reviews)
    )
  `);
  const oldUsers = db.prepare('SELECT * FROM users ORDER BY id').all();

  for (const u of oldUsers) {
    await pgPool.query(`
      INSERT INTO users
      (id, name, email, password_hash, referral_code, referred_by, created_at, status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT DO NOTHING
    `, [u.id, u.name, u.email, u.password_hash, u.referral_code, u.referred_by, u.created_at, u.status]);
  }

  await pgPool.query(`
    SELECT setval(
      pg_get_serial_sequence('users', 'id'),
      GREATEST(COALESCE((SELECT MAX(id) FROM users), 1), 1),
      EXISTS(SELECT 1 FROM users)
    )
  `);

  const result = await pgPool.query('SELECT * FROM users ORDER BY id');

  const syncUsers = db.transaction((users) => {
    for (const u of users) {
      db.prepare(`
        INSERT INTO users
        (id, name, email, password_hash, referral_code, referred_by, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          email=excluded.email,
          password_hash=excluded.password_hash,
          referral_code=excluded.referral_code,
          referred_by=excluded.referred_by,
          created_at=excluded.created_at,
          status=excluded.status
      `).run(Number(u.id), u.name, u.email, u.password_hash, u.referral_code, u.referred_by, u.created_at, u.status);
    }
  });

  syncUsers(result.rows);
}
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
// لعبة الذاكرة اليومية

function memoryGameDate() {
  return new Date().toISOString().slice(0, 10);
}

// عرض حالة اللعبة
app.get('/api/memory-game/status', auth, (req, res) => {
  try {
    const gameDate = memoryGameDate();

    const daily = db.prepare(`
      SELECT attempts_used
      FROM memory_game_daily
      WHERE user_id = ? AND game_date = ?
    `).get(req.userId, gameDate);

    const wins = db.prepare(`
      SELECT COUNT(*) AS total
      FROM memory_game_attempts
      WHERE user_id = ? AND game_date = ? AND status = 'won'
    `).get(req.userId, gameDate);

    const used = daily ? daily.attempts_used : 0;

    res.json({
      attemptsUsed: used,
      attemptsRemaining: Math.max(0, 2 - used),
      winsToday: wins.total
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'تعذر تحميل حالة اللعبة.'
    });
  }
});

// بدء محاولة جديدة
app.post('/api/memory-game/start', auth, (req, res) => {
  try {
    const gameDate = memoryGameDate();

    const symbols = ['🍎', '🚀', '🌟', '🎈'];
    const cards = [...symbols, ...symbols];

    for (let i = cards.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      [cards[i], cards[j]] = [cards[j], cards[i]];
    }

    const attemptId = crypto.randomBytes(16).toString('hex');

    const startGame = db.transaction(() => {
      db.prepare(`
        INSERT OR IGNORE INTO memory_game_daily
        (user_id, game_date, attempts_used)
        VALUES (?, ?, 0)
      `).run(req.userId, gameDate);

      const daily = db.prepare(`
        SELECT attempts_used
        FROM memory_game_daily
        WHERE user_id = ? AND game_date = ?
      `).get(req.userId, gameDate);

      if (daily.attempts_used >= 2) {
        return { error: 'انتهت محاولاتك اليوم. عد غداً.' };
      }

      db.prepare(`
        UPDATE memory_game_daily
        SET attempts_used = attempts_used + 1
        WHERE user_id = ? AND game_date = ?
      `).run(req.userId, gameDate);

      db.prepare(`
        INSERT INTO memory_game_attempts
        (id, user_id, game_date, status, points_awarded)
        VALUES (?, ?, ?, 'started', 0)
      `).run(attemptId, req.userId, gameDate);

      return {
        attemptsUsed: daily.attempts_used + 1,
        attemptsRemaining: 1 - daily.attempts_used
      };
    });

    const result = startGame();

    if (result.error) {
      return res.status(429).json({ error: result.error });
    }

    res.json({
      success: true,
      attemptId,
      cards,
      ...result
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'تعذر بدء اللعبة.'
    });
  }
});

// حفظ نتيجة الفوز
app.post('/api/memory-game/finish', auth, (req, res) => {
  const attemptId = String(req.body?.attemptId || '');

  if (!/^[a-f0-9]{32}$/.test(attemptId)) {
    return res.status(400).json({
      error: 'رقم المحاولة غير صحيح.'
    });
  }

  try {
    const result = db.prepare(`
      UPDATE memory_game_attempts
      SET status = 'won'
      WHERE id = ?
        AND user_id = ?
        AND status = 'started'
    `).run(attemptId, req.userId);

    if (!result.changes) {
      return res.status(404).json({
        error: 'المحاولة غير موجودة أو انتهت.'
      });
    }

    res.json({
      success: true,
      message: 'تم تسجيل الفوز بنجاح.',
      note: 'اللعبة ترفيهية ولا تمنح أموالاً أو مكافآت مالية.'
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'تعذر حفظ نتيجة اللعبة.'
    });
  }
});
app.post('/api/wheel/spin', auth, (req, res) => {
  const submissionId = Number(req.body?.paymentSubmissionId);

  if (!Number.isSafeInteger(submissionId) || submissionId < 1) {
    return res.status(400).json({
      error: 'رقم طلب الإيداع غير صحيح.'
    });
  }

  const prizes = [
    { key: 'grand20m', label: 'الجائزة الكبرى: 20 مليون سنتيم' },
    { key: 'vip', label: 'ترقية مستوى VIP' },
    { key: 'invite2_5000', label: 'ادعُ شخصين واربح 5000 DA' }
  ];

  try {
    const processSpin = db.transaction(() => {
      const submission = db.prepare(`
        SELECT id FROM payment_submissions
        WHERE id = ? AND user_id = ? AND status = 'approved'
      `).get(submissionId, req.userId);

      if (!submission) {
        return {
          error: 'لا يمكنك التدوير قبل اعتماد الإيداع من الإدارة.',
          code: 403
        };
      }

      const existing = db.prepare(`
        SELECT id FROM deposit_wheel_spins
        WHERE payment_submission_id = ?
      `).get(submissionId);

      if (existing) {
        return {
          error: 'لقد استخدمت لفة هذا الإيداع مسبقًا.',
          code: 409
        };
      }

      const prize = prizes[crypto.randomInt(prizes.length)];

      db.prepare(`
        INSERT INTO deposit_wheel_spins
        (user_id, payment_submission_id, prize_key)
        VALUES (?, ?, ?)
      `).run(req.userId, submissionId, prize.key);

      return { prize };
    });

    const result = processSpin();

    if (result.error) {
      return res.status(result.code).json({
        error: result.error
      });
    }

    res.json({
      success: true,
      prize: result.prize,
      financialRewardsEnabled: false,
      message: 'هذه نتيجة تجريبية. الجوائز المالية والترقيات غير مفعلة فعليًا.'
    });

  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'لقد استُخدمت لفة هذا الإيداع مسبقًا.'
      });
    }

    console.error(err);
    res.status(500).json({
      error: 'تعذر تدوير العجلة حاليًا.'
    });
  }
});
  
app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    const code = String(req.body.referralCode || '').trim().toUpperCase();

    if (name.length < 2 || name.length > 80)
      return res.status(400).json({ error: 'أدخل اسمًا صحيحًا (2 إلى 80 حرفًا).' });

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 190)
      return res.status(400).json({ error: 'البريد الإلكتروني غير صحيح.' });

    if (password.length < 8 || password.length > 128)
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل.' });

    const existing = await pgPool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existing.rows.length)
      return res.status(409).json({ error: 'هذا البريد مسجل مسبقًا.' });

    let referrer = null;

    if (code) {
      const ref = await pgPool.query(
        'SELECT id FROM users WHERE referral_code = $1',
        [code]
      );

      if (!ref.rows.length)
        return res.status(400).json({ error: 'كود الدعوة غير صحيح.' });

      referrer = ref.rows[0];
    }

    let rc;

    do {
      rc = referralCode();

      const check = await pgPool.query(
        'SELECT id FROM users WHERE referral_code = $1',
        [rc]
      );

      if (!check.rows.length) break;
    } while (true);

    const hash = await bcrypt.hash(password, 12);

    const result = await pgPool.query(
      `INSERT INTO users
       (name, email, password_hash, referral_code, referred_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, email, hash, rc, referrer ? referrer.id : null]
    );

    const user = result.rows[0];

    db.prepare(`
      INSERT OR IGNORE INTO users
      (id, name, email, password_hash, referral_code, referred_by, created_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      Number(user.id), user.name, user.email, user.password_hash,
      user.referral_code, user.referred_by, user.created_at, user.status
    );

    res.status(201).json({
      token: issueToken(user),
      user: publicUser(user),
      message: 'تم إنشاء الحساب بنجاح.'
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'تعذر إنشاء الحساب حاليًا.' });
  }
});
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');

    const result = await pgPool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user || user.status !== 'active' ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: 'البريد أو كلمة المرور غير صحيحة.'
      });
    }

    res.json({
      token: issueToken(user),
      user: publicUser(user)
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'تعذر تسجيل الدخول حاليًا.'
    });
  }
});
  

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await pgPool.query(
      "SELECT * FROM users WHERE id = $1 AND status = 'active'",
      [req.userId]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: 'الحساب غير موجود أو غير نشط.'
      });
    }

    const referrals = await pgPool.query(
      "SELECT COUNT(*)::int AS n FROM users WHERE referred_by = $1 AND status = 'active'",
      [req.userId]
    );

    const referralCount = referrals.rows[0].n;

    res.json({
      user: publicUser(user),
      referralCount,
      referralGoal: 10,
      proposedRewardDA: referralCount >= 10 ? 5000 : null,
      rewardStatus: 'not_enabled_no_payment',
      notice: 'الوصول إلى 10 دعوات لا ينشئ رصيدًا ماليًا أو حقًا بالدفع تلقائيًا؛ المكافأة غير مفعّلة في النسخة التجريبية.'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: 'تعذر تحميل بيانات الحساب.'
    });
  }
});
// جلب إشعارات المستخدم
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const result = await pgPool.query(
      `SELECT id, title, message, is_read, created_at
       FROM notifications
       WHERE user_id = $1
       ORDER BY id DESC
       LIMIT 50`,
      [req.userId]
    );

    const count = await pgPool.query(
      `SELECT COUNT(*)::int AS count
       FROM notifications
       WHERE user_id = $1 AND is_read = FALSE`,
      [req.userId]
    );

    res.json({
      notifications: result.rows,
      unreadCount: count.rows[0].count
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'تعذر تحميل الإشعارات.' });
  }
});

// تحديد إشعار كمقروء
app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    await pgPool.query(
      `UPDATE notifications
       SET is_read = TRUE
       WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
    );

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'تعذر تحديث الإشعار.' });
  }
});

// تحديد جميع الإشعارات كمقروءة
app.patch('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await pgPool.query(
      `UPDATE notifications
       SET is_read = TRUE
       WHERE user_id = $1`,
      [req.userId]
    );

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'تعذر تحديث الإشعارات.' });
  }
});
app.post('/api/withdrawals', auth, (req, res) => {
  const amount = Number(req.body?.amount);
  const method = String(req.body?.method || '');
  const details = String(req.body?.details || '').trim();

  if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
    return res.status(400).json({ error: 'المبلغ غير صالح.' });
  }

  if (!['BaridiMob', 'CCP', 'RedotPay TRC20'].includes(method)) {
    return res.status(400).json({ error: 'طريقة الاستلام غير صالحة.' });
  }

  if (details.length < 3 || details.length > 200) {
    return res.status(400).json({ error: 'المعلومات غير صالحة.' });
  }

  const result = db.prepare(`
    INSERT INTO withdrawal_requests
    (user_id, amount, method, payout_details)
    VALUES (?, ?, ?, ?)
  `).run(req.userId, amount, method, details);

  res.status(201).json({
    success: true,
    requestId: Number(result.lastInsertRowid),
    status: 'pending',
    message: 'تم تسجيل الطلب التجريبي للمراجعة.'
  });
});
app.get('/api/withdrawals', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, amount, method, status, created_at, reviewed_at
    FROM withdrawal_requests
    WHERE user_id = ?
    ORDER BY id DESC
  `).all(req.userId);

  res.json({ requests: rows });
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
// Support messages - User
app.get('/api/support/messages', auth, (req, res) => {
  const messages = db.prepare(`
    SELECT id, sender, message, created_at
    FROM support_messages
    WHERE user_id = ?
    ORDER BY id ASC
    LIMIT 200
  `).all(req.userId);

  res.json({ messages });
});

app.post('/api/support/messages', auth, (req, res) => {
  const message = String(req.body?.message || '').trim();

  if (!message || message.length > 2000) {
    return res.status(400).json({
      error: 'الرسالة مطلوبة وبحد أقصى 2000 حرف.'
    });
  }

  const result = db.prepare(`
    INSERT INTO support_messages (user_id, sender, message)
    VALUES (?, 'user', ?)
  `).run(req.userId, message);

  res.json({ success: true, id: result.lastInsertRowid });
});

// Support messages - Admin
app.get('/api/admin/support-messages', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!process.env.ADMIN_API_KEY ||
      !safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  const messages = db.prepare(`
    SELECT m.id, m.user_id, m.sender, m.message, m.created_at,
           u.name, u.email
    FROM support_messages m
    JOIN users u ON u.id = m.user_id
    ORDER BY m.id ASC
    LIMIT 1000
  `).all();

  res.json({ messages });
});

app.post('/api/admin/support-messages/:userId', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!process.env.ADMIN_API_KEY ||
      !safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  const userId = Number(req.params.userId);
  const message = String(req.body?.message || '').trim();

  if (!Number.isSafeInteger(userId) || userId < 1 ||
      !message || message.length > 2000) {
    return res.status(400).json({ error: 'بيانات الرسالة غير صحيحة.' });
  }

  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);

  if (!user) {
    return res.status(404).json({ error: 'المستخدم غير موجود.' });
  }

  const result = db.prepare(`
    INSERT INTO support_messages (user_id, sender, message)
    VALUES (?, 'admin', ?)
  `).run(userId, message);

  res.json({ success: true, id: result.lastInsertRowid });
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

// إرسال طلب شراء رصيد إلكتروني
app.post('/api/balance-requests', auth, (req, res) => {
    const {
    balance_type,
    amount,
    requested_quantity,
    custom_balance_name,
    receiver_id,
      receiver_type,
    payment_method,
    receipt_data
  } = req.body || {};

  if (
    typeof balance_type !== 'string' ||
    !balance_type.trim() ||
    balance_type.length > 50
  ) {
    return res.status(400).json({ error: 'نوع الرصيد غير صحيح.' });
  }

    let finalAmount = amount;

  if (balance_type.trim() === "__all_balances__") {
    if (
      typeof requested_quantity !== 'number' ||
      !Number.isFinite(requested_quantity) ||
      requested_quantity <= 0
    ) {
      return res.status(400).json({ error: 'كمية الدولار غير صحيحة.' });
    }

    if (
      typeof custom_balance_name !== 'string' ||
      !custom_balance_name.trim() ||
      custom_balance_name.length > 100
    ) {
      return res.status(400).json({ error: 'اسم البطاقة أو المحفظة غير صحيح.' });
    }

    if (
      typeof receiver_id !== 'string' ||
      !receiver_id.trim() ||
      receiver_id.length > 200
    ) {
      return res.status(400).json({ error: 'معلومات الاستلام غير صحيحة.' });
    }

    finalAmount = Math.round(requested_quantity * 240);
  } else if (
    typeof amount !== 'number' ||
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return res.status(400).json({ error: 'المبلغ غير صحيح.' });
  }

  if (!Number.isFinite(finalAmount) || finalAmount <= 0 || finalAmount > 1000000) {
    return res.status(400).json({ error: 'المبلغ المحسوب غير صحيح.' });
  }

  if (!['BaridiMob', 'CCP'].includes(payment_method)) {
    return res.status(400).json({ error: 'طريقة الدفع غير صحيحة.' });
  }

  if (
    typeof receipt_data !== 'string' ||
    !/^data:image\/(png|jpeg|webp);base64,/.test(receipt_data) ||
    receipt_data.length > 2800000
  ) {
    return res.status(400).json({ error: 'صورة الوصل غير صحيحة.' });
  }

  try {
        const result = db.prepare(`
      INSERT INTO balance_requests
      (
        user_id,
        balance_type,
        amount,
        payment_method,
        receipt_data,
        receiver_id,
        receiver_type,
        requested_quantity,
        custom_balance_name
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.userId,
      balance_type.trim(),
      finalAmount,
      payment_method,
      receipt_data,
      receiver_id || null,
          receiver_type || null,
      balance_type.trim() === "__all_balances__" ? requested_quantity : null,
      balance_type.trim() === "__all_balances__" ? custom_balance_name.trim() : null
    );

    res.status(201).json({
      success: true,
      status: 'pending',
      requestId: Number(result.lastInsertRowid),
      message: 'تم إرسال طلب شراء الرصيد بنجاح، وهو قيد المراجعة.'
    });
  } catch (error) {
    console.error('Balance request error:', error);
    res.status(500).json({ error: 'تعذر إرسال الطلب.' });
  }
});
// عرض طلبات الأرصدة الخاصة بالمستخدم
app.get('/api/my-balance-requests', auth, (req, res) => {
  try {
    const requests = db.prepare(`
      SELECT
        id,
        balance_type,
        amount,
        payment_method,
        status,
        created_at,
        reviewed_at
      FROM balance_requests
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 100
    `).all(req.userId);

    res.json({ requests });
  } catch (error) {
    console.error('My balance requests error:', error);
    res.status(500).json({
      error: 'تعذر جلب طلبات الأرصدة.'
    });
  }
});
// عرض طلبات شراء الأرصدة للإدارة
app.get('/api/admin/balance-requests', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!process.env.ADMIN_API_KEY ||
      !safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  try {
    const requests = db.prepare(`
      SELECT
        b.id,
        b.user_id,
        u.name AS user_name,
        u.email,
        b.balance_type,
        b.amount,
        b.requested_quantity,
b.custom_balance_name,
b.receiver_id,
b.receiver_type,
        b.payment_method,
        b.receipt_data,
        b.status,
        b.created_at
      FROM balance_requests b
      LEFT JOIN users u ON u.id = b.user_id
      ORDER BY b.id DESC
      LIMIT 200
    `).all();

    res.json({ requests });
  } catch (error) {
    console.error('Balance requests error:', error);
    res.status(500).json({
      error: 'تعذر جلب طلبات شراء الأرصدة.'
    });
  }
});

// قبول أو رفض طلب شراء الرصيد
app.patch('/api/admin/balance-requests/:id', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!process.env.ADMIN_API_KEY ||
      !safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  const id = Number(req.params.id);
  const status = String(req.body?.status || '');

  if (!Number.isSafeInteger(id) || id < 1 ||
      !['approved', 'rejected'].includes(status)) {
    return res.status(400).json({
      error: 'بيانات الطلب غير صحيحة.'
    });
  }

  try {
    const result = db.prepare(`
      UPDATE balance_requests
      SET status = ?, reviewed_at = datetime('now')
      WHERE id = ? AND status = 'pending'
    `).run(status, id);

    if (!result.changes) {
      return res.status(404).json({
        error: 'الطلب غير موجود أو تمت مراجعته سابقاً.'
      });
    }

    res.json({
      success: true,
      status,
      message: status === 'approved'
        ? 'تم قبول طلب الرصيد.'
        : 'تم رفض طلب الرصيد.'
    });
  } catch (error) {
    console.error('Balance review error:', error);
    res.status(500).json({
      error: 'تعذرت مراجعة الطلب.'
    });
  }
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
app.patch('/api/me/profile', auth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        error: 'الاسم يجب أن يكون بين حرفين و80 حرفًا.'
      });
    }

    const result = await pgPool.query(
      "UPDATE users SET name = $1 WHERE id = $2 AND status = 'active' RETURNING *",
      [name, req.userId]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        error: 'الحساب غير موجود أو غير نشط.'
      });
    }

    res.json({
      message: 'تم تحديث الاسم بنجاح.',
      user: publicUser(user)
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      error: 'تعذر تحديث الاسم حاليًا.'
    });
  }
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

    const result = await pgPool.query(
      "SELECT * FROM users WHERE id = $1 AND status = 'active'",
      [req.userId]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        error: 'الحساب غير موجود أو غير نشط.'
      });
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

    await pgPool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [hash, req.userId]
    );

    res.json({
      message: 'تم تغيير كلمة المرور بنجاح.'
    });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      error: 'تعذر تغيير كلمة المرور حاليًا.'
    });
  }
});


// عرض طلبات السحب في لوحة الإدارة
app.get('/api/admin/withdrawals', (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (
    !process.env.ADMIN_API_KEY ||
    !safeEqual(key, process.env.ADMIN_API_KEY)
  ) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  try {
    const rows = db.prepare(`
      SELECT w.id, w.user_id, u.name AS user_name,
             u.email, w.amount, w.method,
             w.payout_details, w.status,
             w.created_at, w.reviewed_at
      FROM withdrawal_requests w
      LEFT JOIN users u ON u.id = w.user_id
      ORDER BY w.id DESC
      LIMIT 200
    `).all();

    res.json({ requests: rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'تعذر جلب طلبات السحب.' });
  }
});

// تحديث حالة طلب السحب
app.patch('/api/admin/withdrawals/:id', (req, res) => {
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

  if (!['pending', 'rejected', 'completed'].includes(status)) {
    return res.status(400).json({ error: 'الحالة غير صالحة.' });
  }

  try {
    const result = db.prepare(`
      UPDATE withdrawal_requests
      SET status = ?, reviewed_at = datetime('now')
      WHERE id = ?
    `).run(status, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'الطلب غير موجود.' });
    }

    res.json({
      success: true,
      message: 'تم تحديث حالة الطلب.',
      status
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'تعذر تحديث حالة الطلب.' });
  }
});
// التقييمات العامة: لا يظهر للزوار إلا التقييم المقبول
app.get('/api/reviews', async (req, res) => {
  try {
    const result = await pgPool.query(`
      SELECT id, name, review_text AS text, rating, created_at
      FROM platform_reviews
      WHERE status = 'approved'
      ORDER BY id DESC
      LIMIT 100
    `);

    res.json({ reviews: result.rows });
  } catch (error) {
    console.error('Reviews fetch error:', error);
    res.status(500).json({ error: 'تعذر تحميل التعليقات.' });
  }
});
// استقبال تقييم جديد ووضعه قيد المراجعة
app.post('/api/reviews', async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const reviewText = String(req.body?.text || '').trim();
    const rating = Number(req.body?.rating);

    if (
      name.length < 2 || name.length > 60 ||
      reviewText.length < 5 || reviewText.length > 1000 ||
      !Number.isInteger(rating) || rating < 1 || rating > 5
    ) {
      return res.status(400).json({
        error: 'يرجى إدخال اسم وتعليق صحيحين واختيار تقييم من 1 إلى 5.'
      });
    }

    const result = await pgPool.query(`
      INSERT INTO platform_reviews (name, review_text, rating, status)
      VALUES ($1, $2, $3, 'pending')
      RETURNING id
    `, [name, reviewText, rating]);

    res.status(201).json({
      success: true,
      id: result.rows[0].id,
      message: 'تم استلام تقييمك وسيظهر بعد مراجعته.'
    });
  } catch (error) {
    console.error('Review submission error:', error);
    res.status(500).json({
      error: 'تعذر إرسال التقييم حاليًا.'
    });
  }
});

// عرض التقييمات المعلقة للإدارة
app.get('/api/admin/reviews', async (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  try {
    const result = await pgPool.query(`
      SELECT id, name, review_text AS text, rating, created_at
      FROM platform_reviews
      WHERE status = 'pending'
      ORDER BY id ASC
      LIMIT 500
    `);

    res.json({ reviews: result.rows });
  } catch (error) {
    console.error('Admin reviews fetch error:', error);
    res.status(500).json({ error: 'تعذر تحميل التقييمات.' });
  }
});

// قبول التقييم أو رفضه
app.patch('/api/admin/reviews/:id', async (req, res) => {
  const key = req.get('x-admin-key') || '';

  if (!safeEqual(key, process.env.ADMIN_API_KEY)) {
    return res.status(403).json({ error: 'غير مصرح.' });
  }

  const id = Number(req.params.id);
  const status = String(req.body?.status || '');

  if (!Number.isSafeInteger(id) || id < 1 ||
      !['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'البيانات غير صحيحة.' });
  }

  try {
    const result = await pgPool.query(`
      UPDATE platform_reviews
      SET status = $1
      WHERE id = $2 AND status = 'pending'
      RETURNING id
    `, [status, id]);

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'التقييم غير موجود أو تمت مراجعته سابقًا.'
      });
    }

    res.json({ success: true, message: 'تم تحديث حالة التقييم.' });
  } catch (error) {
    console.error('Review moderation error:', error);
    res.status(500).json({ error: 'تعذر تحديث حالة التقييم.' });
  }
});
app.use(express.static(path.join(__dirname,'public')));
app.use((err,_req,res,_next) => { console.error(err); res.status(500).json({ error: 'خطأ داخلي.' }); });
const port = Number(process.env.PORT || 3000);
initializePersistentUsers()
  .then(() => {
    app.listen(port, () => console.log(`Future AI demo server listening on http://localhost:${port}`));
  })
  .catch(err => {
    console.error('Database initialization failed:', err);
    process.exit(1);
  });
