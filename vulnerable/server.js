/**
 * SecureBank Lab — VERSIÓN VULNERABLE (solo laboratorio local)
 * Fallos intencionales documentados en el README raíz.
 */
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const db = require('./db');

const PORT = process.env.PORT || 3001;
const app = express();

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// A05: sin Helmet / sin headers de seguridad
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

// A07: cookie sin HttpOnly (legible por JS / XSS)
// sameSite lax: None sin Secure lo bloquean Chrome/Safari en http://localhost
app.use(
  session({
    secret: 'weak-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: false, sameSite: 'lax' },
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.appMode = 'vulnerable';
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

// Upload inseguro: cualquier extensión, nombre controlable
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
      const name = req.body.filename || file.originalname;
      cb(null, name);
    },
  }),
});

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
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
  res.render('dashboard', { me, txs });
});

app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  try {
    // Passwords en texto plano
    const info = db
      .prepare('INSERT INTO users (username, password, email, balance) VALUES (?, ?, ?, ?)')
      .run(username, password, email || `${username}@securebank.lab`, 100);
    req.session.user = { id: info.lastInsertRowid, username };
    res.redirect('/');
  } catch (e) {
    req.session.flash = { type: 'error', text: 'No se pudo registrar (¿usuario ya existe?).' };
    res.redirect('/register');
  }
});

// A03: SQL Injection por concatenación
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  let user;
  try {
    user = db.prepare(query).get();
  } catch (e) {
    req.session.flash = { type: 'error', text: 'Error SQL: ' + e.message };
    return res.redirect('/login');
  }
  // A09: sin registro de intentos fallidos
  if (!user) {
    req.session.flash = { type: 'error', text: 'Credenciales incorrectas.' };
    return res.redirect('/login');
  }
  req.session.user = { id: user.id, username: user.username };
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// A03 SQLi + XSS reflected en query
app.get('/search', requireLogin, (req, res) => {
  const q = req.query.q || '';
  let results = [];
  let error = null;
  if (q) {
    const sql = `SELECT t.*, fu.username AS from_name, tu.username AS to_name
      FROM transactions t
      LEFT JOIN users fu ON fu.id = t.from_user_id
      LEFT JOIN users tu ON tu.id = t.to_user_id
      WHERE t.concept LIKE '%${q}%'`;
    try {
      results = db.prepare(sql).all();
    } catch (e) {
      error = e.message;
    }
  }
  res.render('search', { q, results, error });
});

app.get('/transfer', requireLogin, (req, res) => {
  const users = db.prepare('SELECT id, username FROM users WHERE id != ?').all(req.session.user.id);
  res.render('transfer', { users });
});

// CSRF: sin token. Cualquier sitio puede disparar POST si hay sesión.
app.post('/transfer', requireLogin, (req, res) => {
  const toUsername = req.body.to;
  const amount = parseFloat(req.body.amount);
  const concept = req.body.concept || 'Transferencia';
  if (!toUsername || !(amount > 0)) {
    req.session.flash = { type: 'error', text: 'Datos inválidos.' };
    return res.redirect('/transfer');
  }
  const toUser = db.prepare('SELECT * FROM users WHERE username = ?').get(toUsername);
  const fromUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  if (!toUser) {
    req.session.flash = { type: 'error', text: 'Destinatario no existe.' };
    return res.redirect('/transfer');
  }
  if (fromUser.balance < amount) {
    req.session.flash = { type: 'error', text: 'Saldo insuficiente.' };
    return res.redirect('/transfer');
  }
  const transfer = db.transaction(() => {
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, fromUser.id);
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, toUser.id);
    db.prepare(
      'INSERT INTO transactions (from_user_id, to_user_id, amount, concept) VALUES (?, ?, ?, ?)'
    ).run(fromUser.id, toUser.id, amount, concept);
  });
  transfer();
  req.session.flash = { type: 'ok', text: `Transferidos $${amount.toFixed(2)} a ${toUsername}.` };
  res.redirect('/');
});

// A01 IDOR: se puede ver cualquier cuenta cambiando ?id=
app.get('/account', requireLogin, (req, res) => {
  const id = req.query.id || req.session.user.id;
  const account = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!account) {
    req.session.flash = { type: 'error', text: 'Cuenta no encontrada.' };
    return res.redirect('/');
  }
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
  res.render('account', { account, txs });
});

app.get('/messages', requireLogin, (req, res) => {
  const messages = db
    .prepare(
      `SELECT m.*, u.username FROM messages m JOIN users u ON u.id = m.user_id ORDER BY m.id DESC`
    )
    .all();
  res.render('messages', { messages });
});

// XSS stored: body se renderiza sin escape (<%- en la vista)
app.post('/messages', requireLogin, (req, res) => {
  db.prepare('INSERT INTO messages (user_id, body) VALUES (?, ?)').run(
    req.session.user.id,
    req.body.body || ''
  );
  res.redirect('/messages');
});

app.get('/profile', requireLogin, (req, res) => {
  const id = req.query.id || req.session.user.id;
  const profile = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.render('profile', { profile });
});

app.post('/profile/email', requireLogin, (req, res) => {
  // CSRF + se puede apuntar a otro usuario si envían user_id (IDOR)
  const targetId = req.body.user_id || req.session.user.id;
  db.prepare('UPDATE users SET email = ?, bio = ? WHERE id = ?').run(
    req.body.email,
    req.body.bio || '',
    targetId
  );
  req.session.flash = { type: 'ok', text: 'Perfil actualizado.' };
  res.redirect('/profile?id=' + targetId);
});

app.post('/profile/avatar', requireLogin, upload.single('avatar'), (req, res) => {
  if (!req.file) {
    req.session.flash = { type: 'error', text: 'No se subió archivo.' };
    return res.redirect('/profile');
  }
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(req.file.filename, req.session.user.id);
  req.session.flash = { type: 'ok', text: 'Avatar actualizado: ' + req.file.filename };
  res.redirect('/profile');
});

// A10 SSRF: el servidor fetch cualquier URL sin allowlist
app.get('/preview', requireLogin, (req, res) => res.render('preview', { content: null, url: '' }));

app.post('/preview', requireLogin, (req, res) => {
  const target = req.body.url || '';
  let content = '';
  try {
    const u = new URL(target);
    const lib = u.protocol === 'https:' ? https : http;
    const request = lib.get(u, { timeout: 5000 }, (r) => {
      let data = '';
      r.on('data', (chunk) => {
        data += chunk;
        if (data.length > 8000) {
          request.destroy();
        }
      });
      r.on('end', () => {
        content = data.slice(0, 4000);
        res.render('preview', { content, url: target });
      });
    });
    request.on('error', (err) => {
      res.render('preview', { content: 'Error: ' + err.message, url: target });
    });
  } catch (e) {
    res.render('preview', { content: 'URL inválida: ' + e.message, url: target });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`SecureBank VULNERABLE → http://localhost:${PORT}`);
});
