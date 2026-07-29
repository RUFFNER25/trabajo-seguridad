const fs = require('fs');
const path = require('path');
const dbPath = path.join(__dirname, 'data.sqlite');

if (process.argv.includes('--reset') && fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath);
  console.log('Base de datos eliminada.');
}

const db = require('./db');

db.exec('DELETE FROM messages; DELETE FROM transactions; DELETE FROM users;');

const insertUser = db.prepare(
  'INSERT INTO users (username, password, email, balance, bio) VALUES (?, ?, ?, ?, ?)'
);

// INTENCIONAL: passwords en texto plano (A02 / A07)
insertUser.run('alice', 'password123', 'alice@securebank.lab', 1500.0, 'Cliente demo A');
insertUser.run('bob', 'password123', 'bob@securebank.lab', 800.0, 'Cliente demo B');
insertUser.run('admin', 'admin123', 'admin@securebank.lab', 10000.0, 'Administrador demo');

const alice = db.prepare('SELECT id FROM users WHERE username = ?').get('alice');
const bob = db.prepare('SELECT id FROM users WHERE username = ?').get('bob');

const tx = db.prepare(
  'INSERT INTO transactions (from_user_id, to_user_id, amount, concept) VALUES (?, ?, ?, ?)'
);
tx.run(alice.id, bob.id, 50, 'Café campus');
tx.run(bob.id, alice.id, 25, 'Devolución libro');
tx.run(null, alice.id, 1500, 'Depósito inicial');
tx.run(null, bob.id, 800, 'Depósito inicial');

db.prepare('INSERT INTO messages (user_id, body) VALUES (?, ?)').run(
  alice.id,
  'Hola soporte, ¿cuándo llegan los extractos?'
);

console.log('Seed OK (vulnerable). Usuarios: alice/password123, bob/password123, admin/admin123');
