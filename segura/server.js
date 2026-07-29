/**
 * SecureBank Lab — VERSIÓN SEGURA (contraste OWASP)
 */
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const db = require('./db');

const PORT = process.env.PORT || 3002;
const app = express();

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// A05: headers de seguridad
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'script-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'style-src': ["'self'", 'https://fonts.googleapis.com'],
        'font-src': ["'self'", 'https://fonts.gstatic.com'],
        'connect-src': ["'self'"],
      },
    },
  })
);

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

app.use(
  session({
    name: 'securebank.sid',
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // localhost sin HTTPS
      maxAge: 1000 * 60 * 60,
    },
  })
);

const csrfProtection = csrf({ cookie: false });
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiados intentos. Espera unos minutos.',
});

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.appMode = 'segura';
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    req.session.flash = { type: 'error', text: 'Inicia sesión para continuar.' };
    return res.redirect('/login');
  }
  next();
}

function logAuth(username, success, ip) {
  db.prepare('INSERT INTO auth_events (username, success, ip) VALUES (?, ?, ?)').run(
    username || '',
    success ? 1 : 0,
    ip || ''
  );
}

const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp']);
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(16).toString('hex') + ext);
    },
  }),
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
      return cb(new Error('Solo se permiten imágenes: jpg, png, gif, webp'));
    }
    cb(null, true);
  },
  limits: { fileSize: 1 * 1024 * 1024 },
});

const SSRF_ALLOW = new Set(['example.com', 'www.example.com', 'httpbin.org']);

app.get('/', csrfProtection, (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const me = db.prepare('SELECT id, username, email, balance, bio, avatar FROM users WHERE id = ?').get(
    req.session.user.id
  );
  const txs = db
    .prepare(
      `SELECT t.*, fu.username AS from_name, tu.username AS to_name
       FROM transactions t
       LEFT JOIN users fu ON fu.id = t.from_user_id
       LEFT JOIN users tu ON tu.id = t.to_user_id
       WHERE t.from_user_id = ? OR t.to_user_id = ?
       ORDER BY t.id DESC LIMIT 10`
    )
    .all(me.id, me.id);
  res.render('dashboard', { me, txs, csrfToken: req.csrfToken() });
});

app.get('/login', csrfProtection, (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});
app.get('/register', csrfProtection, (req, res) => {
  res.render('register', { csrfToken: req.csrfToken() });
});

app.post('/register', csrfProtection, async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || password.length < 8) {
    req.session.flash = { type: 'error', text: 'Usuario y contraseña (mín. 8) requeridos.' };
    return res.redirect('/register');
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    const info = db
      .prepare('INSERT INTO users (username, password, email, balance) VALUES (?, ?, ?, ?)')
      .run(username, hashed, email || `${username}@securebank.lab`, 100);
    req.session.user = { id: Number(info.lastInsertRowid), username };
    res.redirect('/');
  } catch (e) {
    req.session.flash = { type: 'error', text: 'No se pudo registrar (¿usuario ya existe?).' };
    res.redirect('/register');
  }
});

app.post('/login', loginLimiter, csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = user && (await bcrypt.compare(password || '', user.password));
  if (!ok) {
    logAuth(username, false, req.ip);
    req.session.flash = { type: 'error', text: 'Credenciales incorrectas.' };
    return res.redirect('/login');
  }
  logAuth(username, true, req.ip);
  req.session.regenerate((err) => {
    if (err) {
      req.session.flash = { type: 'error', text: 'Error de sesión.' };
      return res.redirect('/login');
    }
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/');
  });
});

app.post('/logout', csrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/search', requireLogin, csrfProtection, (req, res) => {
  const q = String(req.query.q || '').slice(0, 100);
  let results = [];
  if (q) {
    results = db
      .prepare(
        `SELECT t.*, fu.username AS from_name, tu.username AS to_name
         FROM transactions t
         LEFT JOIN users fu ON fu.id = t.from_user_id
         LEFT JOIN users tu ON tu.id = t.to_user_id
         WHERE t.concept LIKE ?
         ORDER BY t.id DESC LIMIT 50`
      )
      .all('%' + q + '%');
  }
  res.render('search', { q, results, error: null, csrfToken: req.csrfToken() });
});

app.get('/transfer', requireLogin, csrfProtection, (req, res) => {
  const users = db.prepare('SELECT id, username FROM users WHERE id != ?').all(req.session.user.id);
  res.render('transfer', { users, csrfToken: req.csrfToken() });
});

app.post('/transfer', requireLogin, csrfProtection, (req, res) => {
  const toUsername = String(req.body.to || '');
  const amount = parseFloat(req.body.amount);
  const concept = String(req.body.concept || 'Transferencia').slice(0, 120);
  if (!toUsername || !(amount > 0) || amount > 10000) {
    req.session.flash = { type: 'error', text: 'Datos inválidos.' };
    return res.redirect('/transfer');
  }
  const toUser = db.prepare('SELECT * FROM users WHERE username = ?').get(toUsername);
  const fromUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  if (!toUser) {
    req.session.flash = { type: 'error', text: 'Destinatario no existe.' };
    return res.redirect('/transfer');
  }
  if (toUser.id === fromUser.id) {
    req.session.flash = { type: 'error', text: 'No puedes transferirte a ti mismo.' };
    return res.redirect('/transfer');
  }
  if (fromUser.balance < amount) {
    req.session.flash = { type: 'error', text: 'Saldo insuficiente.' };
    return res.redirect('/transfer');
  }
  const transfer = db.transaction(() => {
    const updated = db
      .prepare('UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?')
      .run(amount, fromUser.id, amount);
    if (updated.changes !== 1) throw new Error('Saldo insuficiente');
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, toUser.id);
    db.prepare(
      'INSERT INTO transactions (from_user_id, to_user_id, amount, concept) VALUES (?, ?, ?, ?)'
    ).run(fromUser.id, toUser.id, amount, concept);
  });
  try {
    transfer();
    req.session.flash = { type: 'ok', text: `Transferidos $${amount.toFixed(2)} a ${toUsername}.` };
  } catch (e) {
    req.session.flash = { type: 'error', text: e.message };
  }
  res.redirect('/');
});

// A01 mitigado: solo tu propia cuenta
app.get('/account', requireLogin, csrfProtection, (req, res) => {
  const requested = Number(req.query.id);
  if (requested && requested !== req.session.user.id) {
    req.session.flash = { type: 'error', text: 'Acceso denegado (403): no puedes ver otra cuenta.' };
    return res.redirect('/account');
  }
  const account = db
    .prepare('SELECT id, username, email, balance, bio, avatar FROM users WHERE id = ?')
    .get(req.session.user.id);
  const txs = db
    .prepare(
      `SELECT t.*, fu.username AS from_name, tu.username AS to_name
       FROM transactions t
       LEFT JOIN users fu ON fu.id = t.from_user_id
       LEFT JOIN users tu ON tu.id = t.to_user_id
       WHERE t.from_user_id = ? OR t.to_user_id = ?
       ORDER BY t.id DESC`
    )
    .all(account.id, account.id);
  res.render('account', { account, txs, csrfToken: req.csrfToken() });
});

app.get('/messages', requireLogin, csrfProtection, (req, res) => {
  const messages = db
    .prepare(
      `SELECT m.*, u.username FROM messages m JOIN users u ON u.id = m.user_id ORDER BY m.id DESC`
    )
    .all();
  res.render('messages', { messages, csrfToken: req.csrfToken() });
});

app.post('/messages', requireLogin, csrfProtection, (req, res) => {
  const body = String(req.body.body || '').slice(0, 500);
  db.prepare('INSERT INTO messages (user_id, body) VALUES (?, ?)').run(req.session.user.id, body);
  res.redirect('/messages');
});

app.get('/profile', requireLogin, csrfProtection, (req, res) => {
  const requested = Number(req.query.id);
  if (requested && requested !== req.session.user.id) {
    req.session.flash = { type: 'error', text: 'Acceso denegado: solo tu perfil.' };
    return res.redirect('/profile');
  }
  const profile = db
    .prepare('SELECT id, username, email, balance, bio, avatar FROM users WHERE id = ?')
    .get(req.session.user.id);
  res.render('profile', { profile, csrfToken: req.csrfToken() });
});

app.post('/profile/email', requireLogin, csrfProtection, (req, res) => {
  // Ignora user_id ajeno: siempre el de la sesión
  db.prepare('UPDATE users SET email = ?, bio = ? WHERE id = ?').run(
    String(req.body.email || '').slice(0, 120),
    String(req.body.bio || '').slice(0, 300),
    req.session.user.id
  );
  req.session.flash = { type: 'ok', text: 'Perfil actualizado.' };
  res.redirect('/profile');
});

app.post('/profile/avatar', requireLogin, csrfProtection, (req, res) => {
  upload.single('avatar')(req, res, (err) => {
    if (err) {
      req.session.flash = { type: 'error', text: err.message };
      return res.redirect('/profile');
    }
    if (!req.file) {
      req.session.flash = { type: 'error', text: 'No se subió archivo.' };
      return res.redirect('/profile');
    }
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(req.file.filename, req.session.user.id);
    req.session.flash = { type: 'ok', text: 'Avatar actualizado.' };
    res.redirect('/profile');
  });
});

app.get('/preview', requireLogin, csrfProtection, (req, res) => {
  res.render('preview', { content: null, url: '', csrfToken: req.csrfToken() });
});

app.post('/preview', requireLogin, csrfProtection, (req, res) => {
  const target = String(req.body.url || '');
  try {
    const u = new URL(target);
    if (!['http:', 'https:'].includes(u.protocol)) {
      return res.render('preview', {
        content: 'Solo http/https permitidos.',
        url: target,
        csrfToken: req.csrfToken(),
      });
    }
    if (!SSRF_ALLOW.has(u.hostname)) {
      return res.render('preview', {
        content: `Host no permitido. Allowlist: ${[...SSRF_ALLOW].join(', ')}`,
        url: target,
        csrfToken: req.csrfToken(),
      });
    }
    const lib = u.protocol === 'https:' ? https : http;
    const request = lib.get(u, { timeout: 5000 }, (r) => {
      let data = '';
      r.on('data', (chunk) => {
        data += chunk;
        if (data.length > 8000) request.destroy();
      });
      r.on('end', () => {
        res.render('preview', {
          content: data.slice(0, 4000),
          url: target,
          csrfToken: req.csrfToken(),
        });
      });
    });
    request.on('error', (err) => {
      res.render('preview', {
        content: 'Error: ' + err.message,
        url: target,
        csrfToken: req.csrfToken(),
      });
    });
  } catch (e) {
    res.render('preview', {
      content: 'URL inválida: ' + e.message,
      url: target,
      csrfToken: req.csrfToken(),
    });
  }
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    req.session.flash = { type: 'error', text: 'CSRF rechazado: token inválido o ausente.' };
    return res.redirect('/');
  }
  next(err);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`SecureBank SEGURA → http://localhost:${PORT}`);
});
