// server.js - MajicEarn backend (Railway optimized)
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const cron = require('node-cron');
const multer = require('multer');

// Database connection
const db = require('./config/db');

const app = express();

// ============================
// MULTER CONFIGURATION
// ============================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 1024 * 1024 * 5 // 5MB limit
  }
});

// ============================
// PROXY CONFIGURATION
// ============================
app.set('trust proxy', 1); // Trust Railway's proxy

// ============================
// MIDDLEWARE
// ============================
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Add timeout middleware
app.use((req, res, next) => {
  // Set timeout for all HTTP requests
  req.setTimeout(15000, () => {
    logger.warn(`Request timeout for ${req.method} ${req.url}`);
    res.status(504).json({ error: 'Request timeout' });
  });
  
  // Set timeout for HTTP server response
  res.setTimeout(15000, () => {
    logger.warn(`Response timeout for ${req.method} ${req.url}`);
    if (!res.headersSent) {
      res.status(504).json({ error: 'Response timeout' });
    }
  });
  
  next();
});

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Log middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// ============================
// DATABASE INITIALIZATION
// ============================
let dbInitialized = false;

// Initialize database connection
const initializeApp = async () => {
  try {
    await db.initializeDatabase();
    dbInitialized = true;
    logger.info("✅ Database initialized successfully");
    
    // Run migrations after successful connection
    setTimeout(() => {
      runMigrationsIfNeeded().catch(e => {
        logger.error('❌ Migrations failed:', e.message);
      });
    }, 2000);
    
    return true;
  } catch (err) {
    logger.error("❌ Database initialization failed:", err.message);
    return false;
  }
};

// ============================
// HELPER FUNCTIONS
// ============================
async function runMigrationsIfNeeded() {
  if (!dbInitialized) {
    logger.error("❌ Migration skipped: Database not ready");
    return;
  }
  
  if (process.env.AUTO_MIGRATE !== '1') {
    return;
  }
  
  const schemaPath = path.join(__dirname, 'sql', 'schema.sql');
  if (!fs.existsSync(schemaPath)) {
    logger.error('❌ Migration skipped: schema.sql not found');
    return;
  }
  
  const sql = fs.readFileSync(schemaPath, 'utf8');
  const statements = sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean);
  const conn = await db.getPool().getConnection();
  
  try {
    logger.info('🏃‍♂️ Running migrations...');
    for (const stmt of statements) {
      await conn.query(stmt);
    }
    logger.info('✅ Database schema migrated/ensured.');
  } catch (e) {
    logger.error('❌ Migration failed', e);
  } finally {
    conn.release();
  }
}

function signJwt(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
}

async function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function parseWithdrawalRules(json) {
  try {
    return typeof json === 'string' ? JSON.parse(json) : (json || {});
  } catch {
    return { default: { amount: 10000, fee_rate: 0.15 } };
  }
}

// CSV conversion helper
function convertToCSV(objArray) {
  const array = typeof objArray !== 'object' ? JSON.parse(objArray) : objArray;
  let str = '';

  // Headers
  const headers = Object.keys(array[0]);
  str += headers.join(',') + '\r\n';

  // Rows
  for (let i = 0; i < array.length; i++) {
    let line = '';
    for (let index in headers) {
      if (line !== '') line += ',';
      line += array[i][headers[index]];
    }
    str += line + '\r\n';
  }

  return str;
}

// Database readiness middleware
const checkDbReady = (req, res, next) => {
  if (!dbInitialized) {
    return res.status(503).json({ error: 'Database not ready' });
  }
  next();
};

// Admin authentication middleware
function checkAdminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================
// ROUTES
// ============================

// Root route for Railway health checks
app.get('/', (req, res) => {
  res.json({
    status: "ok",
    message: "MajicEarn Backend is running",
    time: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    dbStatus: dbInitialized ? 'connected' : 'disconnected'
  });
});

// Health check endpoint - FIXED SYNTAX ERROR
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    dbStatus: dbInitialized ? 'connected' : 'disconnected'
  });
});

// Test DB endpoint
app.get('/api/testdb', checkDbReady, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() AS now, CONNECTION_ID() AS conn_id');
    res.json({ 
      success: true, 
      time: rows[0].now,
      connectionId: rows[0].conn_id
    });
  } catch (err) {
    logger.error('DB query failed:', err.message);
    res.status(500).json({ 
      success: false, 
      error: err.message,
      code: err.code
    });
  }
});

// Register - UPDATED to always generate referral code and return it
app.post('/api/register', checkDbReady, async (req, res) => {
  const { username, email, phone, password, referrer_code } = req.body;
  if (!username || !email || !phone || !password) return res.status(400).json({ error: 'Missing fields' });

  const hashed = await bcrypt.hash(password, 10);
  const newUserCode = Math.random().toString(36).slice(2, 10).toUpperCase();

  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();

    const [ins] = await conn.query(
      'INSERT INTO users (username,email,phone,password,referral_code) VALUES (?,?,?,?,?)',
      [username, email, phone, hashed, newUserCode]
    );
    const userId = ins.insertId;

    if (referrer_code) {
      const [rows] = await conn.query('SELECT id FROM users WHERE referral_code=?', [referrer_code]);
      if (rows.length) {
        await conn.query(
          'INSERT INTO referrals (referrer_id, referred_id, referral_date) VALUES (?,?,CURDATE())',
          [rows[0].id, userId]
        );
      }
    }

    await conn.commit();
    const token = signJwt({ id: userId, username });
    res.status(201).json({ token, referral_code: newUserCode });
  } catch (e) {
    await conn.rollback();
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Duplicate entry' });
    logger.error('register failed', { error: e.stack });
    res.status(500).json({ error: 'Server error', code: e.code });
  } finally {
    conn.release();
  }
});

// Login
app.post('/api/login', checkDbReady, async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) return res.status(400).json({ error: 'Missing fields' });
  const conn = await db.getPool().getConnection();
  try {
    const [rows] = await conn.query('SELECT * FROM users WHERE username=? OR email=?', [usernameOrEmail, usernameOrEmail]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signJwt({ id: user.id, username: user.username, referral_code: user.referral_code });
    res.json({ token });
  } catch (e) {
    logger.error('login failed', { error: e.stack });
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Get current user
app.get('/api/user', authenticate, checkDbReady, async (req, res) => {
  const conn = await db.getPool().getConnection();
  try {
    const [rows] = await conn.query('SELECT id, username, email, phone, balance, current_vip_level, referral_code FROM users WHERE id=?', [req.user.id]);
    res.json(rows[0] || null);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Get user profile
app.get('/api/user/profile', authenticate, checkDbReady, async (req, res) => {
  const conn = await db.getPool().getConnection();
  try {
    const [rows] = await conn.query('SELECT id, username, email, phone, balance, current_vip_level, referral_code FROM users WHERE id=?', [req.user.id]);
    res.json(rows[0] || null);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Current balance
app.get('/api/balance', authenticate, checkDbReady, async (req, res) => {
  try {
    const [[row]] = await db.query('SELECT balance FROM users WHERE id=?', [req.user.id]);
    res.json({ balance: Number(row?.balance || 0) });
  } catch (e) {
    logger.error('Error fetching balance:', { error: e.stack, userId: req.user.id });
    res.status(500).json({ error: 'Server error while fetching balance' });
  }
});

// All transactions - FIXED: Removed receipt_url column
app.get('/api/transactions', authenticate, checkDbReady, async (req, res) => {
  try {
    const { type } = req.query;
    const params = [req.user.id];
    let sql = 'SELECT id, type, amount, status, details, account_number, account_name, notes, created_at FROM transactions WHERE user_id=?';
    
    if (type) {
      sql += ' AND type = ?';
      params.push(type);
    }
    sql += ' ORDER BY created_at DESC';
    
    logger.info(`Fetching transactions for user ${req.user.id}, type: ${type || 'all'}`);
    const [rows] = await db.query(sql, params);
    logger.info(`Found ${rows.length} transaction records for user ${req.user.id}`);
    res.json(rows);
  } catch (e) {
    logger.error('Error fetching transactions:', { error: e.stack, userId: req.user.id, type: req.query.type });
    res.status(500).json({ error: 'Server error while fetching transactions' });
  }
});

// Recharge history - FIXED: Removed receipt_url column
app.get('/api/recharge-history', authenticate, checkDbReady, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    
    logger.info(`Fetching recharge history for user ${req.user.id}, page ${page}`);
    
    const [rows] = await db.query(
      `SELECT id, amount, status, account_number, account_name, created_at 
       FROM transactions 
       WHERE user_id=? AND type='recharge' 
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [req.user.id, limit, offset]
    );
    
    // Get total count for pagination info
    const [[countResult]] = await db.query(
      `SELECT COUNT(*) as total FROM transactions WHERE user_id=? AND type='recharge'`,
      [req.user.id]
    );
    
    logger.info(`Found ${rows.length} recharge records for user ${req.user.id}`);
    
    res.json({
      data: rows,
      pagination: {
        current: page,
        limit: limit,
        total: countResult.total,
        pages: Math.ceil(countResult.total / limit)
      }
    });
  } catch (e) {
    logger.error('Error fetching recharge history:', { error: e.stack, userId: req.user.id });
    res.status(500).json({ error: 'Server error while fetching recharge history' });
  }
});

// Withdrawal history
app.get('/api/withdrawal-history', authenticate, checkDbReady, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, amount, status, details, created_at 
       FROM transactions 
       WHERE user_id=? AND type='withdrawal' 
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (e) {
    logger.error('Error fetching withdrawal history:', { error: e.stack, userId: req.user.id });
    res.status(500).json({ error: 'Server error while fetching withdrawal history' });
  }
});

// Change password
app.post('/api/change-password', authenticate, checkDbReady, async (req, res) => {
  const { old_password, new_password, confirm_password } = req.body;
  if (!old_password || !new_password || !confirm_password) return res.status(400).json({ error: 'Missing fields' });
  if (new_password !== confirm_password) return res.status(400).json({ error: 'Passwords do not match' });

  const [[user]] = await db.query('SELECT id, password FROM users WHERE id=?', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const ok = await bcrypt.compare(old_password, user.password);
  if (!ok) return res.status(400).json({ error: 'Old password incorrect' });

  const hashed = await bcrypt.hash(new_password, 10);
  await db.query('UPDATE users SET password=? WHERE id=?', [hashed, req.user.id]);
  res.json({ message: 'Password updated' });
});

// Get VIP levels
app.get('/api/vip-levels', checkDbReady, async (req, res) => {
  const conn = await db.getPool().getConnection();
  try {
    const [rows] = await conn.query('SELECT id, level, price, daily_earnings, earning_days FROM vip_levels ORDER by level ASC');
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Include withdrawal rules in VIP levels response
app.get('/api/vip-levels-with-rules', checkDbReady, async (req, res) => {
  const [rows] = await db.query('SELECT id, level, price, daily_earnings, earning_days, withdrawal_rules FROM vip_levels ORDER by level ASC');
  res.json(rows);
});

// Tasks / Lock status for withdrawals
app.get('/api/tasks-status', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;

  const [[wCount]] = await db.query(
    "SELECT COUNT(*) AS cnt FROM transactions WHERE user_id=? AND type='withdrawal' AND status='approved'",
    [userId]
  );
  const [[rCount]] = await db.query('SELECT COUNT(*) AS cnt FROM referrals WHERE referrer_id=?', [userId]);

  // Your rule: 3rd+ withdrawals require 3 referrals
  const needsReferrals = Number(wCount.cnt) >= 2;
  const hasEnoughReferrals = Number(rCount.cnt) >= 3;

  res.json({
    current_vip_level: req.user.current_vip_level || 0,
    approved_withdrawals: Number(wCount.cnt),
    referrals_count: Number(rCount.cnt),
    withdrawal_locked: needsReferrals && !hasEnoughReferrals,
    requirement: needsReferrals ? '3 referrals required (1 ≥ your level, 2 any level)' : 'None'
  });
});

// Get user tasks and claim status
app.get('/api/tasks', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  
  try {
      // Check if user can claim daily earnings
      const [[lastClaim]] = await db.query(
          `SELECT created_at FROM transactions 
           WHERE user_id = ? AND type = 'daily_earning' 
           ORDER BY created_at DESC LIMIT 1`,
          [userId]
      );
      
      const canClaim = !lastClaim || 
          new Date() - new Date(lastClaim.created_at) > 24 * 60 * 60 * 1000;
      
      const nextClaimTime = lastClaim ? 
          new Date(new Date(lastClaim.created_at).getTime() + 24 * 60 * 60 * 1000) : 
          new Date();
      
      // Get user's VIP level and daily earnings
      const [[user]] = await db.query(
          `SELECT u.current_vip_level, v.daily_earnings 
           FROM users u 
           LEFT JOIN vip_levels v ON u.current_vip_level = v.level 
           WHERE u.id = ?`,
          [userId]
      );
      
      const dailyEarnings = user ? user.daily_earnings || 0 : 0;
      
      // Check referral requirements for withdrawals
      const [[withdrawalCount]] = await db.query(
          "SELECT COUNT(*) AS cnt FROM transactions WHERE user_id = ? AND type = 'withdrawal' AND status = 'approved'",
          [userId]
      );
      
      const [[referralCount]] = await db.query(
          "SELECT COUNT(*) AS cnt FROM referrals WHERE referrer_id = ?",
          [userId]
      );
      
      const needsReferrals = Number(withdrawalCount.cnt) >= 2;
      const requiredReferrals = 3;
      
      res.json({
          can_claim: canClaim && dailyEarnings > 0,
          next_claim_time: nextClaimTime.toISOString(),
          daily_earnings: dailyEarnings,
          referral_requirements: {
              needs_referrals: needsReferrals,
              current_count: Number(referralCount.cnt),
              required_count: requiredReferrals
          }
      });
      
  } catch (error) {
      logger.error('Error fetching tasks:', error);
      res.status(500).json({ error: 'Server error' });
  }
});

// Claim daily earnings
app.post('/api/tasks/claim-daily', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const conn = await db.getPool().getConnection();
  
  try {
      await conn.beginTransaction();
      
      // Check if user can claim (prevent double claiming)
      const [[lastClaim]] = await conn.query(
          `SELECT created_at FROM transactions 
           WHERE user_id = ? AND type = 'daily_earning' 
           ORDER BY created_at DESC LIMIT 1`,
          [userId]
      );
      
      if (lastClaim && (new Date() - new Date(lastClaim.created_at) <= 24 * 60 * 60 * 1000)) {
          await conn.rollback();
          return res.status(400).json({ 
              success: false, 
              message: 'You can only claim once every 24 hours' 
          });
      }
      
      // Get user's daily earnings amount
      const [[user]] = await conn.query(
          `SELECT u.current_vip_level, v.daily_earnings 
           FROM users u 
           LEFT JOIN vip_levels v ON u.current_vip_level = v.level 
           WHERE u.id = ? FOR UPDATE`,
          [userId]
      );
      
      const dailyEarnings = user ? user.daily_earnings || 0 : 0;
      
      if (dailyEarnings <= 0) {
          await conn.rollback();
          return res.status(400).json({ 
              success: false, 
              message: 'No active VIP found for daily earnings' 
          });
      }
      
      // Update user balance
      await conn.query(
          'UPDATE users SET balance = balance + ? WHERE id = ?',
          [dailyEarnings, userId]
      );
      
      // Record transaction
      await conn.query(
          `INSERT INTO transactions (user_id, type, amount, status, details) 
           VALUES (?, 'daily_earning', ?, 'approved', 'Daily VIP earnings')`,
          [userId, dailyEarnings]
      );
      
      await conn.commit();
      
      res.json({ 
          success: true, 
          amount: dailyEarnings,
          message: 'Daily earnings claimed successfully' 
      });
      
  } catch (error) {
      await conn.rollback();
      logger.error('Error claiming daily earnings:', error);
      res.status(500).json({ 
          success: false, 
          message: 'Server error' 
      });
  } finally {
      conn.release();
  }
});

// Announcements
app.get('/api/announcement', checkDbReady, async (req, res) => {
  const [[row]] = await db.query('SELECT id, content, updated_at FROM announcements ORDER by id ASC LIMIT 1');
  res.json(row || { content: '' });
});

// Admin: add VIP
app.post('/api/vip-levels', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });
  const { level, price, daily_earnings, earning_days, withdrawal_rules } = req.body;
  if (!level || !price || !daily_earnings || !earning_days) return res.status(400).json({ error: 'Missing fields' });
  const conn = await db.getPool().getConnection();
  try {
    await conn.query('INSERT INTO vip_levels (level, price, daily_earnings, earning_days, withdrawal_rules) VALUES (?,?,?,?,?)', [level, price, daily_earnings, earning_days, JSON.stringify(withdrawal_rules || {})]);
    res.status(201).json({ message: 'VIP level added' });
  } catch (e) {
    logger.error('add vip failed', { error: e.stack });
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Admin: update announcement
app.put('/admin/announcement', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });
  const { content } = req.body;
  if (typeof content !== 'string') return res.status(400).json({ error: 'content required' });

  const [[row]] = await db.query('SELECT id FROM announcements ORDER by id ASC LIMIT 1');
  if (row) {
    await db.query('UPDATE announcements SET content=? WHERE id=?', [content, row.id]);
  } else {
    await db.query('INSERT INTO announcements (content) VALUES (?)', [content]);
  }
  res.json({ message: 'Announcement updated' });
});

// Admin: list users
app.get('/admin/users', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });

  const [rows] = await db.query('SELECT id, username, email, phone, balance, current_vip_level, referral_code, created_at FROM users ORDER by id DESC');
  res.json(rows);
});

// Admin: adjust balance
app.patch('/admin/users/:id/balance', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });

  const userId = req.params.id;
  const { delta, set } = req.body;

  if (typeof delta !== 'number' && typeof set !== 'number') {
    return res.status(400).json({ error: 'Provide delta or set' });
  }

  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();
    
    if (typeof set === 'number') {
      // Ensure balance doesn't go negative
      if (set < 0) {
        await conn.rollback();
        return res.status(400).json({ error: 'Balance cannot be negative' });
      }
      await conn.query('UPDATE users SET balance=? WHERE id=?', [set, userId]);
    } else {
      // Check if the delta would make balance negative
      const [[user]] = await conn.query('SELECT balance FROM users WHERE id=? FOR UPDATE', [userId]);
      const newBalance = Number(user.balance) + delta;
      if (newBalance < 0) {
        await conn.rollback();
        return res.status(400).json({ error: 'Balance cannot be negative' });
      }
      await conn.query('UPDATE users SET balance=balance+? WHERE id=?', [delta, userId]);
    }
    
    await conn.commit();
    res.json({ message: 'Balance updated' });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Admin: get user details with transactions and referrals
app.get('/admin/users/:id/details', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });

  const userId = req.params.id;
  try {
    // Get user details
    const [[user]] = await db.query(
      'SELECT id, username, email, phone, balance, current_vip_level, referral_code, created_at FROM users WHERE id = ?',
      [userId]
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get user transactions
    const [transactions] = await db.query(
      'SELECT id, type, amount, status, details, account_number, account_name, notes, created_at FROM transactions WHERE user_id = ? ORDER by created_at DESC',
      [userId]
    );

    // Get user referrals
    const [referrals] = await db.query(
      `SELECT u.id, u.username, u.phone, r.referral_date, r.first_recharge_bonus_paid
       FROM referrals r
       JOIN users u ON r.referred_id = u.id
       WHERE r.referrer_id = ?`,
      [userId]
    );

    // Get user VIP purchases
    const [vipPurchases] = await db.query(
      `SELECT p.id, v.level, v.price, p.purchase_date, p.expiry_date, p.active
       FROM user_vip_purchases p
       JOIN vip_levels v ON p.vip_level_id = v.id
       WHERE p.user_id = ?
       ORDER by p.purchase_date DESC`,
      [userId]
    );

    res.json({
      user,
      transactions,
      referrals,
      vipPurchases
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Purchase VIP with 90-day validity and one purchase per level restriction
app.post('/api/purchase-vip', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const { vip_level_id } = req.body;
  if (!vip_level_id) return res.status(400).json({ error: 'vip_level_id required' });
  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();
    
    // Check if user already has an active purchase of this VIP level
    const [existingPurchases] = await conn.query(
      'SELECT id FROM user_vip_purchases WHERE user_id = ? AND vip_level_id = ? AND active = 1 AND expiry_date >= CURDATE()',
      [userId, vip_level_id]
    );
    
    if (existingPurchases.length > 0) {
      throw new Error('You already have an active purchase of this VIP level');
    }
    
    const [[vip]] = await conn.query('SELECT * FROM vip_levels WHERE id=?', [vip_level_id]);
    if (!vip) throw new Error('VIP not found');
    const [[user]] = await conn.query('SELECT id, balance, current_vip_level FROM users WHERE id=? FOR UPDATE', [userId]);
    if (!user) throw new Error('User not found');
    if (Number(user.balance) < Number(vip.price)) throw new Error('Insufficient balance');
    await conn.query('UPDATE users SET balance = balance - ? WHERE id = ?', [vip.price, userId]);
    await conn.query("INSERT INTO transactions (user_id, type, amount, status, details) VALUES (?, 'vip_purchase', ?, 'approved', ?)", [userId, vip.price, `Purchased VIP level ${vip.level}`]);
    const purchaseDate = new Date();
    const expiry = new Date(purchaseDate); 
    expiry.setDate(expiry.getDate() + 90); // 90-day validity
    
    await conn.query('INSERT INTO user_vip_purchases (user_id, vip_level_id, purchase_date, expiry_date, active) VALUES (?,?,?,?,1)', [userId, vip_level_id, purchaseDate.toISOString().slice(0,10), expiry.toISOString().slice(0,10)]);
    const [maxRow] = await conn.query(`SELECT MAX(v.level) as maxLevel FROM user_vip_purchases p JOIN vip_levels v ON p.vip_level_id = v.id WHERE p.user_id=? AND p.active=1`, [userId]);
    const maxLevel = maxRow[0].maxLevel || 0;
    if (maxLevel > (user.current_vip_level || 0)) {
      await conn.query('UPDATE users SET current_vip_level=? WHERE id=?', [maxLevel, userId]);
    }
    await conn.commit();
    res.json({ message: 'VIP purchased' });
  } catch (e) {
    await conn.rollback();
    logger.error('purchase vip failed', { error: e.stack });
    res.status(400).json({ error: e.message || 'Server error' });
  } finally {
    conn.release();
  }
});

// VIP purchase endpoint (alias)
app.post('/api/vip/purchase', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const { vip_level_id } = req.body;
  if (!vip_level_id) return res.status(400).json({ error: 'vip_level_id required' });
  
  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();
    
    // Check if user already has an active purchase of this VIP level
    const [existingPurchases] = await conn.query(
      'SELECT id FROM user_vip_purchases WHERE user_id = ? AND vip_level_id = ? AND active = 1 AND expiry_date >= CURDATE()',
      [userId, vip_level_id]
    );
    
    if (existingPurchases.length > 0) {
      throw new Error('You already have an active purchase of this VIP level');
    }
    
    const [[vip]] = await conn.query('SELECT * FROM vip_levels WHERE id=?', [vip_level_id]);
    if (!vip) throw new Error('VIP not found');
    const [[user]] = await conn.query('SELECT id, balance, current_vip_level FROM users WHERE id=? FOR UPDATE', [userId]);
    if (!user) throw new Error('User not found');
    if (Number(user.balance) < Number(vip.price)) throw new Error('Insufficient balance');
    
    await conn.query('UPDATE users SET balance = balance - ? WHERE id = ?', [vip.price, userId]);
    await conn.query("INSERT INTO transactions (user_id, type, amount, status, details) VALUES (?, 'vip_purchase', ?, 'approved', ?)", 
      [userId, vip.price, `Purchased VIP level ${vip.level}`]);
    
    const purchaseDate = new Date();
    const expiry = new Date(purchaseDate); 
    expiry.setDate(expiry.getDate() + 90); // 90-day validity
    
    await conn.query('INSERT INTO user_vip_purchases (user_id, vip_level_id, purchase_date, expiry_date, active) VALUES (?,?,?,?,1)', 
      [userId, vip_level_id, purchaseDate.toISOString().slice(0,10), expiry.toISOString().slice(0,10)]);
    
    const [maxRow] = await conn.query(`SELECT MAX(v.level) as maxLevel FROM user_vip_purchases p JOIN vip_levels v ON p.vip_level_id = v.id WHERE p.user_id=? AND p.active=1`, [userId]);
    const maxLevel = maxRow[0].maxLevel || 0;
    
    if (maxLevel > (user.current_vip_level || 0)) {
      await conn.query('UPDATE users SET current_vip_level=? WHERE id=?', [maxLevel, userId]);
    }
    
    await conn.commit();
    res.json({ message: 'VIP purchased' });
  } catch (e) {
    await conn.rollback();
    logger.error('purchase vip failed', { error: e.stack });
    res.status(400).json({ error: e.message || 'Server error' });
  } finally {
    conn.release();
  }
});

// Recharge
app.post('/api/recharge', authenticate, upload.single('receipt'), checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const amountRaw = req.body.amount;
  const account_number = (req.body.account_number || '').trim();
  const account_name = (req.body.account_name || '').trim();

  const amt = Number(amountRaw);
  if (!amt || amt < 1000) {
    return res.status(400).json({ error: 'Amount must be at least 1000 PKR' });
  }
  if (!account_number || !account_name) {
    return res.status(400).json({ error: 'Account number and account name are required' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Receipt is required' });
  }

  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();

    const receiptBuffer = req.file.buffer;
    const fileName = req.file.originalname;
    const fileType = req.file.mimetype;

    await conn.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, details, account_number, account_name, receipt_data, receipt_filename, receipt_type)
       VALUES (?, 'recharge', ?, 'pending', 'User submitted recharge', ?, ?, ?, ?, ?)`,
      [userId, amt, account_number, account_name, receiptBuffer, fileName, fileType]
    );

    await conn.commit();
    res.status(201).json({ 
      message: 'Recharge submitted and is pending review. Approval usually takes up to 5 hours. Contact us on WhatsApp if needed.', 
      amount: amt,
      note: "Please keep your receipt safe for verification. Approval typically takes up to 5 hours."
    });
  } catch (e) {
    await conn.rollback();
    return res.status(500).json({ error: 'Server error: ' + e.message });
  } finally {
    conn.release();
  }
});

// Withdraw - Enhanced with account locking, unique validation, and VIP referral requirements
app.post('/api/withdraw', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const { account_number, account_name, amount } = req.body;
  const amt = Number(amount);
  
  if (!amt || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });
  
  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();
    
    // Get user details with account info
    const [[user]] = await conn.query(
      'SELECT id, balance, current_vip_level, withdrawal_account_number, withdrawal_account_name FROM users WHERE id=? FOR UPDATE', 
      [userId]
    );
    
    if (!user) throw new Error('User not found');
    
    // Check if user already has a saved account
    let finalAccountNumber = user.withdrawal_account_number;
    let finalAccountName = user.withdrawal_account_name;
    
    if (finalAccountNumber) {
      // User already has an account saved - ignore provided values
      if (account_number && account_number !== finalAccountNumber) {
        throw new Error('Account number cannot be changed after first withdrawal');
      }
    } else {
      // First withdrawal - validate and save account details
      if (!account_number || !account_name) {
        throw new Error('Account number and name are required for first withdrawal');
      }
      
      // Check if account number is already used by another user
      const [[existingAccount]] = await conn.query(
        'SELECT id FROM users WHERE withdrawal_account_number = ? AND id != ?',
        [account_number, userId]
      );
      
      if (existingAccount) {
        throw new Error('This account number is already registered by another user');
      }
      
      // Save account details
      await conn.query(
        'UPDATE users SET withdrawal_account_number = ?, withdrawal_account_name = ? WHERE id = ?',
        [account_number, account_name, userId]
      );
      
      finalAccountNumber = account_number;
      finalAccountName = account_name;
    }
    
    // Check balance
    if (Number(user.balance) < amt) throw new Error('Insufficient balance');
    
    // Get withdrawal rules based on VIP level
    const [vrRow] = await conn.query(
      'SELECT withdrawal_rules FROM vip_levels WHERE level=?', 
      [user.current_vip_level || 0]
    );
    
    const rules = parseWithdrawalRules(vrRow && vrRow.length ? vrRow[0].withdrawal_rules : '{}');
    
    // Count previous approved withdrawals
    const [countRow] = await conn.query(
      "SELECT COUNT(*) as cnt FROM transactions WHERE user_id=? AND type='withdrawal' AND status='approved'", 
      [userId]
    );
    
    const withdrawalCount = countRow[0].cnt || 0;
    const applicable = rules[String(withdrawalCount + 1)] || rules.default || { amount: 10000, fee_rate: 0.15 };
    
    // Validate amount against limit
    if (amt > Number(applicable.amount)) {
      throw new Error(`Maximum withdrawal for this request is Rs ${applicable.amount}. Your limit is based on your VIP level and withdrawal count.`);
    }
    
    // Check referral requirement for 3rd+ withdrawals
    if (withdrawalCount >= 2) {
      const [rCount] = await conn.query('SELECT COUNT(*) as cnt FROM referrals WHERE referrer_id=?', [userId]);
      if (rCount[0].cnt < 3) {
        throw new Error('Complete referral tasks first. You need at least 3 referrals for additional withdrawals.');
      }

      // For VIP level 1 and above, check if at least one referral has VIP level equal or higher
      if (user.current_vip_level >= 1) {
        const [refRows] = await conn.query(
          `SELECT u.current_vip_level 
           FROM referrals r 
           JOIN users u ON r.referred_id = u.id 
           WHERE r.referrer_id = ?`,
          [userId]
        );
        const hasEqualOrHigher = refRows.some(ref => ref.current_vip_level >= user.current_vip_level);
        if (!hasEqualOrHigher) {
          throw new Error(`For this withdrawal, you need at least one referral with VIP level ${user.current_vip_level} or higher.`);
        }
      }
    }
    
    // Calculate fee and net amount
    const fee = Math.round(amt * Number(applicable.fee_rate || 0.15) * 100) / 100;
    const net = Math.round((amt - fee) * 100) / 100;
    
    // Final balance check
    const finalBalance = Number(user.balance) - amt;
    if (finalBalance < 0) throw new Error('Insufficient balance after fee calculation');
    
    // Update balance and create transaction
    await conn.query('UPDATE users SET balance = balance - ? WHERE id=?', [amt, userId]);
    await conn.query(
      "INSERT INTO transactions (user_id, type, amount, status, details) VALUES (?, 'withdrawal', ?, 'pending', ?)", 
      [userId, amt, `Acct:${finalAccountNumber}|Name:${finalAccountName}|Fee:${fee}|Net:${net}|WithdrawalNumber:${withdrawalCount + 1}`]
    );
    
    await conn.commit();
    
    res.json({ 
      message: 'Withdrawal submitted', 
      fee, 
      net_amount: net,
      account_locked: !!user.withdrawal_account_number, // Tell frontend if account is now locked
      note: "Withdrawal processing typically takes 24-48 hours. Contact us on WhatsApp for urgent queries."
    });
    
  } catch (e) {
    await conn.rollback();
    logger.error('withdraw failed', { error: e.stack });
    res.status(400).json({ error: e.message || 'Server error' });
  } finally {
    conn.release();
  }
});

// Get withdrawal limits for current user
app.get('/api/withdrawal-limits', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const conn = await db.getPool().getConnection();
  
  try {
    // Get user's VIP level
    const [[user]] = await conn.query(
      'SELECT current_vip_level FROM users WHERE id=?', 
      [userId]
    );
    
    // Get withdrawal rules for this VIP level
    const [vrRow] = await conn.query(
      'SELECT withdrawal_rules FROM vip_levels WHERE level=?', 
      [user.current_vip_level || 0]
    );
    
    const rules = parseWithdrawalRules(vrRow && vrRow.length ? vrRow[0].withdrawal_rules : '{}');
    
    // Count previous approved withdrawals
    const [countRow] = await conn.query(
      "SELECT COUNT(*) as cnt FROM transactions WHERE user_id=? AND type='withdrawal' AND status='approved'", 
      [userId]
    );
    
    const withdrawalCount = countRow[0].cnt || 0;
    const nextWithdrawalRule = rules[String(withdrawalCount + 1)] || rules.default || { amount: 10000, fee_rate: 0.15 };
    
    // Check if user has saved account details
    const [[accountInfo]] = await conn.query(
      'SELECT withdrawal_account_number, withdrawal_account_name FROM users WHERE id=?',
      [userId]
    );
    
    res.json({
      vip_level: user.current_vip_level || 0,
      withdrawal_count: withdrawalCount,
      next_withdrawal_limit: nextWithdrawalRule.amount,
      fee_rate: nextWithdrawalRule.fee_rate,
      has_saved_account: !!accountInfo.withdrawal_account_number,
      account_number: accountInfo.withdrawal_account_number,
      account_name: accountInfo.withdrawal_account_name
    });
    
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Team
app.get('/api/team', authenticate, checkDbReady, async (req, res) => {
  const userId = req.user.id;
  const conn = await db.getPool().getConnection();
  try {
    const [members] = await conn.query(
      `SELECT u.id, u.username, u.phone,
              SUM(CASE WHEN t.type='recharge' AND t.status='approved' THEN t.amount ELSE 0 END) AS total_recharge,
              SUM(CASE WHEN t.type='withdrawal' AND t.status IN ('pending','approved') THEN t.amount ELSE 0 END) AS total_withdrawal
       FROM referrals r
       JOIN users u ON r.referred_id = u.id
       LEFT JOIN transactions t ON u.id = t.user_id
       WHERE r.referrer_id = ?
       GROUP by u.id`, [userId]
    );
    const [[me]] = await conn.query('SELECT referral_code FROM users WHERE id=?', [userId]);
    const [[earnRow]] = await conn.query("SELECT SUM(amount) as total FROM transactions WHERE user_id=? AND type='referral_bonus'", [userId]);
    res.json({ referral_link: `${process.env.BASE_URL}/signup?ref=${me.referral_code}`, referral_earnings: Number(earnRow.total||0), team_members: members });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Admin: list withdrawals
app.get('/admin/withdrawals', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(503).json({ error: 'Admin only' });
  const conn = await db.getPool().getConnection();
  try {
    const [rows] = await conn.query(`SELECT t.*, u.username, u.email, u.phone FROM transactions t JOIN users u ON t.user_id = u.id WHERE t.type='withdrawal' ORDER by t.created_at DESC`);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Admin: list recharges
app.get('/admin/recharges', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });

  const conn = await db.getPool().getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT t.id, t.user_id, t.amount, t.status, t.account_number, t.account_name, 
              t.receipt_filename, t.receipt_type, t.created_at, t.notes,
              u.username, u.email, u.phone
       FROM transactions t 
       JOIN users u ON t.user_id = u.id
       WHERE t.type='recharge'
       ORDER by t.created_at DESC`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Admin: view receipt - FIXED to force download
app.get('/admin/receipt/:transactionId', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });
  
  const transactionId = req.params.transactionId;
  
  try {
    const [[transaction]] = await db.query(
      'SELECT receipt_data, receipt_type, receipt_filename FROM transactions WHERE id = ? AND type = "recharge"',
      [transactionId]
    );
    
    if (!transaction || !transaction.receipt_data) {
      return res.status(404).json({ error: 'Receipt not found' });
    }
    
    // Set headers to force download
    res.setHeader('Content-Type', transaction.receipt_type);
    res.setHeader('Content-Disposition', `attachment; filename="${transaction.receipt_filename}"`);
    
    // Send the binary data
    res.send(transaction.receipt_data);
  } catch (e) {
    logger.error('Error fetching receipt:', { error: e.stack, transactionId });
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: approve/reject a recharge
app.put('/admin/recharges/:id', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });

  const id = req.params.id;
  const { status, notes } = req.body;
  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();

    const [[trx]] = await conn.query(
      'SELECT id, user_id, amount, status FROM transactions WHERE id=? AND type="recharge" FOR UPDATE',
      [id]
    );
    if (!trx) {
      await conn.rollback();
      return res.status(404).json({ error: 'Recharge not found' });
    }
    if (trx.status !== 'pending') {
      await conn.rollback();
      return res.status(400).json({ error: 'Only pending recharges can be updated' });
    }

    if (status === 'approved') {
      await conn.query('UPDATE users SET balance = balance + ? WHERE id=?', [trx.amount, trx.user_id]);

      const [[countRow]] = await conn.query(
        "SELECT COUNT(*) AS cnt FROM transactions WHERE user_id=? AND type='recharge' AND status='approved'",
        [trx.user_id]
      );
  const wasZeroBefore = Number(countRow.cnt) === 0;
      if (wasZeroBefore) {
        const [[refRow]] = await conn.query('SELECT referrer_id, first_recharge_bonus_paid FROM referrals WHERE referred_id=? FOR UPDATE', [trx.user_id]);
        if (refRow && refRow.referrer_id && !refRow.first_recharge_bonus_paid) {
          const bonus = Math.round(Number(trx.amount) * 0.08 * 100) / 100;
          await conn.query('UPDATE users SET balance = balance + ? WHERE id=?', [bonus, refRow.referrer_id]);
          await conn.query(
            "INSERT INTO transactions (user_id, type, amount, status, details) VALUES (?, 'referral_bonus', ?, 'approved', 'First recharge referral bonus')",
            [refRow.referrer_id, bonus]
          );
          await conn.query('UPDATE referrals SET first_recharge_bonus_paid=1 WHERE referred_id=?', [trx.user_id]);
        }
      }
    }

    await conn.query('UPDATE transactions SET status=?, notes=? WHERE id=?', [status, notes || null, id]);
    await conn.commit();
    res.json({ message: 'Recharge updated' });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Admin: override user account lock
app.put('/admin/users/:id/account-lock', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Admin only' });
  }

  const userId = req.params.id;
  const { unlock } = req.body; // Set to true to unlock account

  try {
    if (unlock) {
      await db.query(
        'UPDATE users SET withdrawal_account_number = NULL, withdrawal_account_name = NULL WHERE id = ?',
        [userId]
      );
      res.json({ message: 'Account lock removed' });
    } else {
      res.json({ message: 'No changes made' });
    }
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: process withdrawals
app.put('/admin/withdrawals/:id', checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });
  
  const id = req.params.id;
  const { status } = req.body;
  if (!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  
  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();
    
    if (status === 'rejected') {
      const [[trx]] = await conn.query('SELECT user_id, amount FROM transactions WHERE id=? AND type="withdrawal" FOR UPDATE', [id]);
      if (trx) {
        // Rollback balance
        await conn.query('UPDATE users SET balance = balance + ? WHERE id=?', [trx.amount, trx.user_id]);
        
        // Record rollback transaction
        await conn.query(
          "INSERT INTO transactions (user_id, type, amount, status, details, reference_id) VALUES (?, 'rollback', ?, 'success', ?, ?)",
          [trx.user_id, trx.amount, `Rollback for withdrawal #${id}`, id]
        );
        
        // Mark original transaction as failed
        await conn.query(
          "UPDATE transactions SET status = 'failed' WHERE id = ? AND type = 'withdrawal'",
          [id]
        );
      }
    } else {
      // For approval, just update status
      const [result] = await conn.query(
        "UPDATE transactions SET status = 'approved' WHERE id = ? AND type = 'withdrawal' AND status = 'pending'",
        [id]
      );

      if (result.affectedRows === 0) {
        await conn.rollback();
        return res.status(400).json({ error: "Withdrawal not found or already processed" });
      }
      
      // Mark as success in transaction history
      await conn.query(
        "UPDATE transactions SET status = 'success' WHERE reference_id = ? AND type = 'withdrawal'",
        [id]
      );
    }
    
    await conn.commit();
    res.json({ message: 'Withdrawal processed successfully' });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Get all pending withdrawals for admin
app.get("/api/admin/withdrawals/pending", checkDbReady, async (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Admin only' });

  try {
    const [rows] = await db.query(
      `SELECT t.id, t.user_id, u.username, u.current_vip_level as vip_level, t.amount, t.created_at, t.details
       FROM transactions t
       JOIN users u ON t.user_id = u.id
       WHERE t.type = 'withdrawal' AND t.status = 'pending'
       ORDER BY t.created_at ASC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Debug endpoint to check user's recharge transactions
app.get('/api/debug/recharge', authenticate, checkDbReady, async (req, res) => {
  try {
    // Check if user exists
    const [[user]] = await db.query('SELECT id, username FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check transaction count
    const [[count]] = await db.query(
      'SELECT COUNT(*) as count FROM transactions WHERE user_id = ? AND type = "recharge"',
      [req.user.id]
    );
    
    // Check if there are any very large records
    const [largeRecords] = await db.query(
      `SELECT id, LENGTH(details) as details_length, 
              LENGTH(account_number) as account_number_length,
              LENGTH(account_name) as account_name_length
       FROM transactions 
       WHERE user_id = ? AND type = "recharge"
       ORDER BY created_at DESC 
       LIMIT 5`,
      [req.user.id]
    );
    
    res.json({
      user: { id: user.id, username: user.username },
      recharge_count: count.count,
      largest_records: largeRecords
    });
  } catch (e) {
    logger.error('Debug error:', { error: e.stack, userId: req.user.id });
    res.status(500).json({ error: 'Debug error: ' + e.message });
  }
});

// ============================
// NEW ADMIN ENDPOINTS
// ============================

// Admin authentication
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Check if admin credentials are correct
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid admin credentials' });
    }
});

// Admin stats
app.get('/api/admin/stats', checkAdminAuth, async (req, res) => {
    try {
        // Get total users
        const [[userCount]] = await db.query('SELECT COUNT(*) as total FROM users');
        
        // Get total revenue
        const [[revenue]] = await db.query(`
            SELECT SUM(amount) as total FROM transactions 
            WHERE type IN ('recharge', 'vip_purchase') AND status = 'approved'
        `);
        
        // Get total transactions
        const [[transactionCount]] = await db.query('SELECT COUNT(*) as total FROM transactions');
        
        // Get pending actions
        const [[pendingCount]] = await db.query(`
            SELECT COUNT(*) as total FROM transactions 
            WHERE status = 'pending'
        `);
        
        res.json({
            totalUsers: userCount.total,
            totalRevenue: revenue.total || 0,
            totalTransactions: transactionCount.total,
            pendingActions: pendingCount.total
        });
    } catch (error) {
        logger.error('Failed to fetch admin stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Recent activity
app.get('/api/admin/recent-activity', checkAdminAuth, async (req, res) => {
    try {
        // Get recent user registrations
        const [userRegistrations] = await db.query(`
            SELECT username, created_at as timestamp 
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 5
        `);
        
        // Get recent transactions
        const [transactions] = await db.query(`
            SELECT t.*, u.username 
            FROM transactions t 
            JOIN users u ON t.user_id = u.id 
            ORDER BY t.created_at DESC 
            LIMIT 5
        `);
        
        // Format activities
        const activities = [];
        
        userRegistrations.forEach(user => {
            activities.push({
                type: 'user_registered',
                message: `New user registered: ${user.username}`,
                timestamp: user.timestamp
            });
        });
        
        transactions.forEach(transaction => {
            let message = '';
            if (transaction.type === 'recharge') {
                message = `Recharge from ${transaction.username}: Rs. ${transaction.amount}`;
            } else if (transaction.type === 'withdrawal') {
                message = `Withdrawal request from ${transaction.username}: Rs. ${transaction.amount}`;
            } else if (transaction.type === 'vip_purchase') {
                message = `VIP purchase by ${transaction.username}: Rs. ${transaction.amount}`;
            }
            
            activities.push({
                type: transaction.type,
                message: message,
                timestamp: transaction.created_at
            });
        });
        
        // Sort by timestamp
        activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        res.json(activities.slice(0, 5));
    } catch (error) {
        logger.error('Failed to fetch recent activity:', error);
        res.status(500).json({ error: 'Failed to fetch activity' });
    }
});

// Revenue data
app.get('/api/admin/revenue-data', checkAdminAuth, async (req, res) => {
    try {
        const days = parseInt(req.query.days) || 7;
        const data = [];
        const labels = [];
        
        // Generate data for the last X days
        for (let i = days - 1; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateString = date.toISOString().split('T')[0];
            
            // Get revenue for this date
            const [[revenue]] = await db.query(`
                SELECT SUM(amount) as total FROM transactions 
                WHERE DATE(created_at) = ? 
                AND type IN ('recharge', 'vip_purchase') 
                AND status = 'approved'
            `, [dateString]);
            
            data.push(revenue.total || 0);
            labels.push(dateString);
        }
        
        res.json({ data, labels });
    } catch (error) {
        logger.error('Failed to fetch revenue data:', error);
        res.status(500).json({ error: 'Failed to fetch revenue data' });
    }
});

// User management endpoints
app.get('/api/admin/users', checkAdminAuth, async (req, res) => {
    try {
        const [users] = await db.query(`
            SELECT id, username, email, phone, balance, current_vip_level, status, created_at 
            FROM users 
            ORDER BY id DESC
        `);
        res.json(users);
    } catch (error) {
        logger.error('Failed to fetch users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/users/:id', checkAdminAuth, async (req, res) => {
    try {
        const userId = req.params.id;
        const [[user]] = await db.query(`
            SELECT id, username, email, phone, balance, current_vip_level, status, created_at 
            FROM users 
            WHERE id = ?
        `, [userId]);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        logger.error('Failed to fetch user:', error);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

app.get('/api/admin/users/:id/details', checkAdminAuth, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Get user details
        const [[user]] = await db.query(`
            SELECT id, username, email, phone, balance, current_vip_level, status, created_at 
            FROM users 
            WHERE id = ?
        `, [userId]);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Get user transactions
        const [transactions] = await db.query(`
            SELECT id, type, amount, status, created_at 
            FROM transactions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        `, [userId]);
        
        // Get user referrals
        const [referrals] = await db.query(`
            SELECT u.username, u.phone, r.referral_date 
            FROM referrals r 
            JOIN users u ON r.referred_id = u.id 
            WHERE r.referrer_id = ?
        `, [userId]);
        
        // Get user VIP purchases
        const [vipPurchases] = await db.query(`
            SELECT p.*, v.level, v.price 
            FROM user_vip_purchases p 
            JOIN vip_levels v ON p.vip_level_id = v.id 
            WHERE p.user_id = ? 
            ORDER BY p.purchase_date DESC
        `, [userId]);
        
        res.json({
            user,
            transactions,
            referrals,
            vipPurchases
        });
    } catch (error) {
        logger.error('Failed to fetch user details:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

app.post('/api/admin/users', checkAdminAuth, async (req, res) => {
    const { username, email, phone, password, balance, vip_level } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const conn = await db.getPool().getConnection();
    
    try {
        await conn.beginTransaction();
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generate referral code
        const referralCode = Math.random().toString(36).slice(2, 10).toUpperCase();
        
        // Create user
        const [result] = await conn.query(`
            INSERT INTO users (username, email, phone, password, balance, current_vip_level, referral_code, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
        `, [username, email, phone, hashedPassword, balance || 0, vip_level || 0, referralCode]);
        
        // Update balance if provided
        if (balance && balance > 0) {
            await conn.query(`
                INSERT INTO transactions (user_id, type, amount, status, details)
                VALUES (?, 'admin_adjustment', ?, 'approved', 'Initial balance adjustment by admin')
            `, [result.insertId, balance]);
        }
        
        await conn.commit();
        
        res.json({ message: 'User created successfully', userId: result.insertId });
    } catch (error) {
        await conn.rollback();
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        
        logger.error('Failed to create user:', error);
        res.status(500).json({ error: 'Failed to create user' });
    } finally {
        conn.release();
    }
});

app.put('/api/admin/users/:id', checkAdminAuth, async (req, res) => {
    const userId = req.params.id;
    const { username, email, phone, balance, vip_level, status } = req.body;
    
    const conn = await db.getPool().getConnection();
    
    try {
        await conn.beginTransaction();
        
        // Get current user data
        const [[user]] = await conn.query('SELECT balance FROM users WHERE id = ?', [userId]);
        
        if (!user) {
            await conn.rollback();
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Update user
        await conn.query(`
            UPDATE users 
            SET username = ?, email = ?, phone = ?, current_vip_level = ?, status = ?
            WHERE id = ?
        `, [username, email, phone, vip_level, status, userId]);
        
        // Adjust balance if changed
        const balanceDiff = balance - user.balance;
        if (balanceDiff !== 0) {
            await conn.query('UPDATE users SET balance = ? WHERE id = ?', [balance, userId]);
            
            await conn.query(`
                INSERT INTO transactions (user_id, type, amount, status, details)
                VALUES (?, 'admin_adjustment', ?, 'approved', ?)
            `, [userId, Math.abs(balanceDiff), balanceDiff > 0 ? 
                'Balance increased by admin' : 'Balance decreased by admin']);
        }
        
        await conn.commit();
        
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        await conn.rollback();
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        
        logger.error('Failed to update user:', error);
        res.status(500).json({ error: 'Failed to update user' });
    } finally {
        conn.release();
    }
});

app.delete('/api/admin/users/:id', checkAdminAuth, async (req, res) => {
    const userId = req.params.id;
    
    try {
        // Check if user exists
        const [[user]] = await db.query('SELECT id FROM users WHERE id = ?', [userId]);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Delete user (you might want to soft delete instead)
        await db.query('DELETE FROM users WHERE id = ?', [userId]);
        
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        logger.error('Failed to delete user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// ============================
// VIP MANAGEMENT ENDPOINTS
// ============================

// VIP Management Endpoints
app.get('/api/admin/vip-levels', checkAdminAuth, async (req, res) => {
    try {
        const [vipLevels] = await db.query('SELECT * FROM vip_levels ORDER BY level');
        res.json({ data: vipLevels });
    } catch (error) {
        logger.error('Failed to fetch VIP levels:', error);
        res.status(500).json({ error: 'Failed to fetch VIP levels' });
    }
});

app.get('/api/admin/vip-levels/:id', checkAdminAuth, async (req, res) => {
    try {
        const vipId = req.params.id;
        const [[vipLevel]] = await db.query('SELECT * FROM vip_levels WHERE id = ?', [vipId]);
        
        if (!vipLevel) {
            return res.status(404).json({ error: 'VIP level not found' });
        }
        
        res.json({ data: vipLevel });
    } catch (error) {
        logger.error('Failed to fetch VIP level:', error);
        res.status(500).json({ error: 'Failed to fetch VIP level' });
    }
});

app.post('/api/admin/vip-levels', checkAdminAuth, async (req, res) => {
    const { level, name, price, daily_earnings, duration, status, description } = req.body;
    
    if (!level || !name || !price || !daily_earnings || !duration || !status) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    try {
        const [result] = await db.query(`
            INSERT INTO vip_levels (level, name, price, daily_earnings, duration, status, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [level, name, price, daily_earnings, duration, status, description]);
        
        res.json({ message: 'VIP level created successfully', id: result.insertId });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'VIP level already exists' });
        }
        
        logger.error('Failed to create VIP level:', error);
        res.status(500).json({ error: 'Failed to create VIP level' });
    }
});

app.put('/api/admin/vip-levels/:id', checkAdminAuth, async (req, res) => {
    const vipId = req.params.id;
    const { level, name, price, daily_earnings, duration, status, description } = req.body;
    
    try {
        // Check if VIP level exists
        const [[vipLevel]] = await db.query('SELECT id FROM vip_levels WHERE id = ?', [vipId]);
        
        if (!vipLevel) {
            return res.status(404).json({ error: 'VIP level not found' });
        }
        
        // Update VIP level
        await db.query(`
            UPDATE vip_levels 
            SET level = ?, name = ?, price = ?, daily_earnings = ?, duration = ?, status = ?, description = ?
            WHERE id = ?
        `, [level, name, price, daily_earnings, duration, status, description, vipId]);
        
        res.json({ message: 'VIP level updated successfully' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'VIP level already exists' });
        }
        
        logger.error('Failed to update VIP level:', error);
        res.status(500).json({ error: 'Failed to update VIP level' });
    }
});

app.delete('/api/admin/vip-levels/:id', checkAdminAuth, async (req, res) => {
    const vipId = req.params.id;
    
    try {
        // Check if VIP level exists
        const [[vipLevel]] = await db.query('SELECT id FROM vip_levels WHERE id = ?', [vipId]);
        
        if (!vipLevel) {
            return res.status(404).json({ error: 'VIP level not found' });
        }
        
        // Delete VIP level
        await db.query('DELETE FROM vip_levels WHERE id = ?', [vipId]);
        
        res.json({ message: 'VIP level deleted successfully' });
    } catch (error) {
        logger.error('Failed to delete VIP level:', error);
        res.status(500).json({ error: 'Failed to delete VIP level' });
    }
});

// ============================
// TRANSACTIONS ENDPOINTS
// ============================

// Get all transactions with filters
app.get('/api/admin/transactions', checkAdminAuth, async (req, res) => {
    try {
        const { type, status, date_from, date_to, page = 1, limit = 10 } = req.query;
        
        let query = `
            SELECT t.*, u.username 
            FROM transactions t 
            LEFT JOIN users u ON t.user_id = u.id 
            WHERE 1=1
        `;
        let params = [];
        
        if (type) {
            query += ' AND t.type = ?';
            params.push(type);
        }
        
        if (status) {
            query += ' AND t.status = ?';
            params.push(status);
        }
        
        if (date_from) {
            query += ' AND DATE(t.created_at) >= ?';
            params.push(date_from);
        }
        
        if (date_to) {
            query += ' AND DATE(t.created_at) <= ?';
            params.push(date_to);
        }
        
        query += ' ORDER BY t.created_at DESC';
        
        // Add pagination
        const offset = (page - 1) * limit;
        query += ' LIMIT ? OFFSET ?';
        params.push(parseInt(limit), offset);
        
        const [transactions] = await db.query(query, params);
        
        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as total FROM transactions t WHERE 1=1';
        let countParams = [];
        
        if (type) {
            countQuery += ' AND t.type = ?';
            countParams.push(type);
        }
        
        if (status) {
            countQuery += ' AND t.status = ?';
            countParams.push(status);
        }
        
        if (date_from) {
            countQuery += ' AND DATE(t.created_at) >= ?';
            countParams.push(date_from);
        }
        
        if (date_to) {
            countQuery += ' AND DATE(t.created_at) <= ?';
            countParams.push(date_to);
        }
        
        const [[{ total }]] = await db.query(countQuery, countParams);
        
        res.json({
            data: transactions,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        logger.error('Failed to fetch transactions:', error);
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

// Get single transaction
app.get('/api/admin/transactions/:id', checkAdminAuth, async (req, res) => {
    try {
        const transactionId = req.params.id;
        const [[transaction]] = await db.query(`
            SELECT t.*, u.username 
            FROM transactions t 
            LEFT JOIN users u ON t.user_id = u.id 
            WHERE t.id = ?
        `, [transactionId]);
        
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }
        
        res.json({ data: transaction });
    } catch (error) {
        logger.error('Failed to fetch transaction:', error);
        res.status(500).json({ error: 'Failed to fetch transaction' });
    }
});

// Approve transaction
app.put('/api/admin/transactions/:id/approve', checkAdminAuth, async (req, res) => {
    const transactionId = req.params.id;
    const conn = await db.getPool().getConnection();
    
    try {
        await conn.beginTransaction();
        
        // Get transaction details
        const [[transaction]] = await conn.query(`
            SELECT * FROM transactions WHERE id = ? AND status = 'pending'
        `, [transactionId]);
        
        if (!transaction) {
            await conn.rollback();
            return res.status(404).json({ error: 'Pending transaction not found' });
        }
        
        // Update transaction status
        await conn.query(`
            UPDATE transactions SET status = 'approved', processed_at = NOW() WHERE id = ?
        `, [transactionId]);
        
        // If it's a recharge or VIP purchase, update user balance
        if (transaction.type === 'recharge' || transaction.type === 'vip_purchase') {
            await conn.query(`
                UPDATE users SET balance = balance + ? WHERE id = ?
            `, [transaction.amount, transaction.user_id]);
        }
        
        // If it's a withdrawal, deduct from user balance
        if (transaction.type === 'withdrawal') {
            await conn.query(`
                UPDATE users SET balance = balance - ? WHERE id = ?
            `, [transaction.amount, transaction.user_id]);
        }
        
        await conn.commit();
        res.json({ message: 'Transaction approved successfully' });
    } catch (error) {
        await conn.rollback();
        logger.error('Failed to approve transaction:', error);
        res.status(500).json({ error: 'Failed to approve transaction' });
    } finally {
        conn.release();
    }
});

// Reject transaction
app.put('/api/admin/transactions/:id/reject', checkAdminAuth, async (req, res) => {
    const transactionId = req.params.id;
    
    try {
        // Update transaction status
        await db.query(`
            UPDATE transactions SET status = 'rejected', processed_at = NOW() WHERE id = ?
        `, [transactionId]);
        
        res.json({ message: 'Transaction rejected successfully' });
    } catch (error) {
        logger.error('Failed to reject transaction:', error);
        res.status(500).json({ error: 'Failed to reject transaction' });
    }
});

// Export transactions
app.get('/api/admin/transactions/export', checkAdminAuth, async (req, res) => {
    try {
        const { type, status, date_from, date_to } = req.query;
        
        let query = `
            SELECT t.*, u.username 
            FROM transactions t 
            LEFT JOIN users u ON t.user_id = u.id 
            WHERE 1=1
        `;
        let params = [];
        
        if (type) {
            query += ' AND t.type = ?';
            params.push(type);
        }
        
        if (status) {
            query += ' AND t.status = ?';
            params.push(status);
        }
        
        if (date_from) {
            query += ' AND DATE(t.created_at) >= ?';
            params.push(date_from);
        }
        
        if (date_to) {
            query += ' AND DATE(t.created_at) <= ?';
            params.push(date_to);
        }
        
        query += ' ORDER BY t.created_at DESC';
        
        const [transactions] = await db.query(query, params);
        
        // Convert to CSV
        const csv = convertToCSV(transactions);
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=transactions.csv');
        res.send(csv);
    } catch (error) {
        logger.error('Failed to export transactions:', error);
        res.status(500).json({ error: 'Failed to export transactions' });
    }
});

// ============================
// ANNOUNCEMENTS ENDPOINTS
// ============================

// Announcements Endpoints
app.get('/api/admin/announcements', checkAdminAuth, async (req, res) => {
    try {
        const [announcements] = await db.query('SELECT * FROM announcements ORDER BY created_at DESC');
        res.json({ data: announcements });
    } catch (error) {
        logger.error('Failed to fetch announcements:', error);
        res.status(500).json({ error: 'Failed to fetch announcements' });
    }
});

app.get('/api/admin/announcements/:id', checkAdminAuth, async (req, res) => {
    try {
        const announcementId = req.params.id;
        const [[announcement]] = await db.query('SELECT * FROM announcements WHERE id = ?', [announcementId]);
        
        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }
        
        res.json({ data: announcement });
    } catch (error) {
        logger.error('Failed to fetch announcement:', error);
        res.status(500).json({ error: 'Failed to fetch announcement' });
    }
});

app.post('/api/admin/announcements', checkAdminAuth, async (req, res) => {
    const { title, content, status } = req.body;
    
    if (!title || !content || !status) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    try {
        const [result] = await db.query(`
            INSERT INTO announcements (title, content, status)
            VALUES (?, ?, ?)
        `, [title, content, status]);
        
        res.json({ message: 'Announcement created successfully', id: result.insertId });
    } catch (error) {
        logger.error('Failed to create announcement:', error);
        res.status(500).json({ error: 'Failed to create announcement' });
    }
});

app.put('/api/admin/announcements/:id', checkAdminAuth, async (req, res) => {
    const announcementId = req.params.id;
    const { title, content, status } = req.body;
    
    try {
        // Check if announcement exists
        const [[announcement]] = await db.query('SELECT id FROM announcements WHERE id = ?', [announcementId]);
        
        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }
        
        // Update announcement
        await db.query(`
            UPDATE announcements 
            SET title = ?, content = ?, status = ?
            WHERE id = ?
        `, [title, content, status, announcementId]);
        
        res.json({ message: 'Announcement updated successfully' });
    } catch (error) {
        logger.error('Failed to update announcement:', error);
        res.status(500).json({ error: 'Failed to update announcement' });
    }
});

app.delete('/api/admin/announcements/:id', checkAdminAuth, async (req, res) => {
    const announcementId = req.params.id;
    
    try {
        // Check if announcement exists
        const [[announcement]] = await db.query('SELECT id FROM announcements WHERE id = ?', [announcementId]);
        
        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }
        
        // Delete announcement
        await db.query('DELETE FROM announcements WHERE id = ?', [announcementId]);
        
        res.json({ message: 'Announcement deleted successfully' });
    } catch (error) {
        logger.error('Failed to delete announcement:', error);
        res.status(500).json({ error: 'Failed to delete announcement' });
    }
});

// ============================
// TASKS ENDPOINTS
// ============================

// Tasks Endpoints
app.get('/api/admin/tasks', checkAdminAuth, async (req, res) => {
    try {
        const [tasks] = await db.query('SELECT * FROM tasks ORDER BY created_at DESC');
        res.json({ data: tasks });
    } catch (error) {
        logger.error('Failed to fetch tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

app.get('/api/admin/tasks/:id', checkAdminAuth, async (req, res) => {
    try {
        const taskId = req.params.id;
        const [[task]] = await db.query('SELECT * FROM tasks WHERE id = ?', [taskId]);
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json({ data: task });
    } catch (error) {
        logger.error('Failed to fetch task:', error);
        res.status(500).json({ error: 'Failed to fetch task' });
    }
});

app.post('/api/admin/tasks', checkAdminAuth, async (req, res) => {
    const { title, description, reward, status } = req.body;
    
    if (!title || !description || !reward || !status) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    try {
        const [result] = await db.query(`
            INSERT INTO tasks (title, description, reward, status)
            VALUES (?, ?, ?, ?)
        `, [title, description, reward, status]);
        
        res.json({ message: 'Task created successfully', id: result.insertId });
    } catch (error) {
        logger.error('Failed to create task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

app.put('/api/admin/tasks/:id', checkAdminAuth, async (req, res) => {
    const taskId = req.params.id;
    const { title, description, reward, status } = req.body;
    
    try {
        // Check if task exists
        const [[task]] = await db.query('SELECT id FROM tasks WHERE id = ?', [taskId]);
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        // Update task
        await db.query(`
            UPDATE tasks 
            SET title = ?, description = ?, reward = ?, status = ?
            WHERE id = ?
        `, [title, description, reward, status, taskId]);
        
        res.json({ message: 'Task updated successfully' });
    } catch (error) {
        logger.error('Failed to update task:', error);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

app.delete('/api/admin/tasks/:id', checkAdminAuth, async (req, res) => {
    const taskId = req.params.id;
    
    try {
        // Check if task exists
        const [[task]] = await db.query('SELECT id FROM tasks WHERE id = ?', [taskId]);
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        // Delete task
        await db.query('DELETE FROM tasks WHERE id = ?', [taskId]);
        
        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        logger.error('Failed to delete task:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

// ============================
// TEAM ENDPOINTS
// ============================

// Team Endpoints
app.get('/api/admin/team', checkAdminAuth, async (req, res) => {
    try {
        const [team] = await db.query('SELECT id, name, email, role, status, last_login FROM admin_users ORDER BY created_at DESC');
        res.json({ data: team });
    } catch (error) {
        logger.error('Failed to fetch team:', error);
        res.status(500).json({ error: 'Failed to fetch team' });
    }
});

app.get('/api/admin/team/:id', checkAdminAuth, async (req, res) => {
    try {
        const memberId = req.params.id;
        const [[member]] = await db.query('SELECT id, name, email, role, status, last_login FROM admin_users WHERE id = ?', [memberId]);
        
        if (!member) {
            return res.status(404).json({ error: 'Team member not found' });
        }
        
        res.json({ data: member });
    } catch (error) {
        logger.error('Failed to fetch team member:', error);
        res.status(500).json({ error: 'Failed to fetch team member' });
    }
});

app.post('/api/admin/team', checkAdminAuth, async (req, res) => {
    const { name, email, password, role, status } = req.body;
    
    if (!name || !email || !password || !role || !status) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const [result] = await db.query(`
            INSERT INTO admin_users (name, email, password, role, status)
            VALUES (?, ?, ?, ?, ?)
        `, [name, email, hashedPassword, role, status]);
        
        res.json({ message: 'Team member created successfully', id: result.insertId });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email already exists' });
        }
        
        logger.error('Failed to create team member:', error);
        res.status(500).json({ error: 'Failed to create team member' });
    }
});

app.put('/api/admin/team/:id', checkAdminAuth, async (req, res) => {
    const memberId = req.params.id;
    const { name, email, password, role, status } = req.body;
    
    try {
        // Check if team member exists
        const [[member]] = await db.query('SELECT id FROM admin_users WHERE id = ?', [memberId]);
        
        if (!member) {
            return res.status(404).json({ error: 'Team member not found' });
        }
        
        // Build update query
        let query = 'UPDATE admin_users SET name = ?, email = ?, role = ?, status = ?';
        let params = [name, email, role, status];
        
        // Add password to update if provided
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password = ?';
            params.push(hashedPassword);
        }
        
        query += ' WHERE id = ?';
        params.push(memberId);
        
        // Update team member
        await db.query(query, params);
        
        res.json({ message: 'Team member updated successfully' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email already exists' });
        }
        
        logger.error('Failed to update team member:', error);
        res.status(500).json({ error: 'Failed to update team member' });
    }
});

app.delete('/api/admin/team/:id', checkAdminAuth, async (req, res) => {
    const memberId = req.params.id;
    
    try {
        // Check if team member exists
        const [[member]] = await db.query('SELECT id FROM admin_users WHERE id = ?', [memberId]);
        
        if (!member) {
            return res.status(404).json({ error: 'Team member not found' });
        }
        
        // Don't allow deletion of the last admin
        const [[adminCount]] = await db.query('SELECT COUNT(*) as count FROM admin_users WHERE role = "admin"');
        if (adminCount.count <= 1) {
            return res.status(400).json({ error: 'Cannot delete the last admin user' });
        }
        
        // Delete team member
        await db.query('DELETE FROM admin_users WHERE id = ?', [memberId]);
        
        res.json({ message: 'Team member deleted successfully' });
    } catch (error) {
        logger.error('Failed to delete team member:', error);
        res.status(500).json({ error: 'Failed to delete team member' });
    }
});

// ============================
// SETTINGS ENDPOINTS
// ============================

// Settings Endpoints
app.get('/api/admin/settings', checkAdminAuth, async (req, res) => {
    try {
        const [settings] = await db.query('SELECT * FROM settings WHERE id = 1');
        
        if (settings.length === 0) {
            // Create default settings if not exists
            await db.query(`
                INSERT INTO settings (id, site_name, site_url, admin_email, currency, min_withdrawal, referral_commission, maintenance_mode, maintenance_message)
                VALUES (1, 'MajicEarn', 'https://majicearn.com', 'admin@majicearn.com', 'PKR', 500, 8, 0, '')
            `);
            
            const [[newSettings]] = await db.query('SELECT * FROM settings WHERE id = 1');
            return res.json({ data: newSettings });
        }
        
        res.json({ data: settings[0] });
    } catch (error) {
        logger.error('Failed to fetch settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/admin/settings', checkAdminAuth, async (req, res) => {
    const { site_name, site_url, admin_email, currency, min_withdrawal, referral_commission, maintenance_mode, maintenance_message } = req.body;
    
    try {
        await db.query(`
            UPDATE settings 
            SET site_name = ?, site_url = ?, admin_email = ?, currency = ?, min_withdrawal = ?, referral_commission = ?, maintenance_mode = ?, maintenance_message = ?
            WHERE id = 1
        `, [site_name, site_url, admin_email, currency, min_withdrawal, referral_commission, maintenance_mode, maintenance_message]);
        
        res.json({ message: 'Settings updated successfully' });
    } catch (error) {
        logger.error('Failed to update settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ============================
// CRON JOBS
// ============================
// Daily earnings cron job - Enhanced to prevent earnings from expired VIPs
cron.schedule('10 0 * * *', async () => {
  if (!dbInitialized) {
    logger.error('Daily earnings failed: Database not ready');
    return;
  }
  
  const conn = await db.getPool().getConnection();
  try {
    await conn.beginTransaction();
    
    // First, deactivate any expired VIP purchases
    await conn.query('UPDATE user_vip_purchases SET active = 0 WHERE expiry_date < CURDATE() AND active = 1');
    
    // Then process earnings only for active, non-expired VIP purchases
    const [rows] = await conn.query(
      `SELECT p.user_id, v.daily_earnings, p.id as purchase_id
       FROM user_vip_purchases p
       JOIN vip_levels v ON p.vip_level_id = v.id
       WHERE p.active = 1 AND p.expiry_date >= CURDATE()`
    );
    
    for (const r of rows) {
      await conn.query('UPDATE users SET balance = balance + ? WHERE id=?', [r.daily_earnings, r.user_id]);
      await conn.query("INSERT INTO transactions (user_id, type, amount, status, details) VALUES (?, 'earning', ?, 'approved', 'Daily VIP earnings')", [r.user_id, r.daily_earnings]);
    }
    
    await conn.commit();
    logger.info('✅ Daily earnings processed successfully');
  } catch (e) {
    await conn.rollback();
    logger.error('daily earnings failed', { error: e.stack });
  } finally {
    conn.release();
  }
}, { timezone: 'UTC' });

// VIP expiration cron job - FIXED to use active column
cron.schedule("5 0 * * *", async () => {
  if (!dbInitialized) {
    logger.error('VIP expiration failed: Database not ready');
    return;
  }
  
  try {
    await db.query(
      "UPDATE user_vip_purchases SET active = 0 WHERE expiry_date < CURDATE() AND active = 1"
    );
    logger.info("Expired VIPs updated.");
  } catch (err) {
    logger.error("Error expiring VIPs:", err);
  }
}, { timezone: 'UTC' });

// ============================
// START SERVER
// ============================
const PORT = process.env.PORT || 3001;
const HOST = '0.0.0.0';

// Initialize the application and start the server
const startServer = async () => {
  try {
    // Initialize database first
    const dbSuccess = await initializeApp();
    
    if (!dbSuccess) {
      logger.error("Failed to initialize database, shutting down");
      process.exit(1);
    }
    
    // Start server on the correct port
    const server = app.listen(PORT, HOST, () => {
      logger.info(`🚀 API listening on ${HOST}:${PORT}`);
    });
    
    // Handle shutdown gracefully
    process.on('SIGINT', () => {
      logger.info('SIGINT received - shutting down');
      shutdown(server);
    });

    process.on('SIGTERM', () => {
      logger.info('SIGTERM received - shutting down');
      shutdown(server);
    });
    
    return server;
  } catch (error) {
    logger.error("Failed to start server:", error);
    process.exit(1);
  }
};

function shutdown(server) {
  logger.info('Starting shutdown process...');
  
  server.close(() => {
    logger.info('HTTP server closed');
    
    // Close database pool
    if (db.getPool()) {
      db.getPool().end(err => {
        if (err) logger.error('Error closing database pool:', err);
        else logger.info('Database pool closed');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });

  // Force shutdown after timeout
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
}

// Log unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Log uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start the server
startServer().then(server => {
  logger.info("Server started successfully on port " + PORT);
}).catch(error => {
  logger.error("Failed to start server:", error);
  process.exit(1);
});
