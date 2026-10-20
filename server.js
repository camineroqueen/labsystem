const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_COOKIE = 'labconnect_session';
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_SECURE = process.env.NODE_ENV === 'production';
const databasePath = process.env.DB_PATH || path.join(__dirname, 'labconnect.db');
const db = new sqlite3.Database(databasePath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log(`Connected to SQLite database: ${databasePath}`);
  }
});
db.configure('busyTimeout', 5000);
db.run('PRAGMA foreign_keys = ON');

let transactionQueue = Promise.resolve();

app.use(express.json({ limit: '16kb' }));

function sendPage(fileName, res) {
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, fileName));
}

app.get(['/', '/index.html'], (req, res) => sendPage('index.html', res));
app.get('/dashboard.html', (req, res) => sendPage('dashboard.html', res));

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || '';
  const cookie = cookieHeader.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return cookie ? cookie.slice(name.length + 1) : null;
}

function writeSessionCookie(res, token) {
  const secure = COOKIE_SECURE ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION_MS / 1000}${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = COOKIE_SECURE ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`
  );
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function runTransaction(work) {
  const transaction = transactionQueue.then(() => new Promise((resolve, reject) => {
    db.run('BEGIN IMMEDIATE', (beginErr) => {
      if (beginErr) {
        reject(beginErr);
        return;
      }

      const run = (sql, params = []) => new Promise((resolveQuery, rejectQuery) => {
        db.run(sql, params, function (queryErr) {
          if (queryErr) rejectQuery(queryErr);
          else resolveQuery({ changes: this.changes, lastID: this.lastID });
        });
      });

      Promise.resolve()
        .then(() => work(run))
        .then((result) => run('COMMIT').then(() => resolve(result)))
        .catch((err) => {
          db.run('ROLLBACK', (rollbackErr) => {
            if (rollbackErr) console.error('Failed to roll back database transaction:', rollbackErr.message);
            reject(err);
          });
        });
    });
  }));
  transactionQueue = transaction.catch(() => {});
  return transaction;
}

function createSession(userId, res, user) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_DURATION_MS;
  db.run(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    [tokenHash(token), userId, expiresAt],
    (err) => {
      if (err) {
        console.error('Failed to create login session:', err.message);
        return res.status(500).json({ error: 'Could not create a login session.' });
      }
      writeSessionCookie(res, token);
      res.json({ message: 'Login successful!', user });
    }
  );
}

function requireAuth(req, res, next) {
  const token = getCookie(req, SESSION_COOKIE);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(401).json({ error: 'Please log in to continue.' });
  }

  db.get(
    `SELECT users.id, users.student_id, users.full_name, users.role
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ? AND sessions.expires_at > ?`,
    [tokenHash(token), Date.now()],
    (err, user) => {
      if (err) {
        console.error('Failed to validate login session:', err.message);
        return res.status(500).json({ error: 'Could not validate your login session.' });
      }
      if (!user) {
        clearSessionCookie(res);
        return res.status(401).json({ error: 'Your login session has expired. Please log in again.' });
      }
      req.user = user;
      next();
    }
  );
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator access is required.' });
  }
  next();
}

function initializeDatabase() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        full_name TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'student'
      )
    `, (err) => {
      if (err) console.error('Failed to initialize users table:', err.message);
    });

    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `, (err) => {
      if (err) console.error('Failed to initialize sessions table:', err.message);
    });

    db.run(`
      CREATE TABLE IF NOT EXISTS equipment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        stock INTEGER DEFAULT 10,
        icon TEXT,
        color_class TEXT,
        description TEXT
      )
    `, (err) => {
      if (err) {
        console.error('Failed to initialize equipment table:', err.message);
        return;
      }

      initializeRequestsTable();
      db.get('SELECT COUNT(*) AS count FROM equipment', [], (countErr, row) => {
        if (countErr) {
          console.error('Failed to check equipment records:', countErr.message);
          return;
        }
        if (row.count !== 0) return;

        const initialItems = [
          ['First Aid Medical Kit', 'First Aid', 10, 'fa-kit-medical', 'icon-red', 'Bandages, antiseptic & gauze'],
          ['Portable Instant Ice Packs', 'First Aid', 15, 'fa-snowflake', 'icon-cyan', 'Cold compress for sprains/bumps'],
          ['Folding Clinic Stretcher', 'First Aid', 4, 'fa-bed-pulse', 'icon-purple', 'Emergency student transport'],
          ['Standard Clinic Wheelchair', 'First Aid', 0, 'fa-wheelchair', 'icon-orange', 'Mobility assistance wheelchair'],
          ['Test Tube Set with Wooden Rack', 'Chemistry', 20, 'fa-vial', 'icon-green', 'Standard glass test tubes'],
          ['Glass Beaker Set (250ml & 500ml)', 'Chemistry', 18, 'fa-glass-water', 'icon-green', 'Borosilicate glassware'],
          ['Erlenmeyer Flask (250ml)', 'Chemistry', 14, 'fa-flask', 'icon-green', 'Cone flask for titrations'],
          ['Graduated Cylinder (100ml)', 'Chemistry', 0, 'fa-flask-vial', 'icon-purple', 'Volume measurement cylinder'],
          ['Compound Microscope', 'Laboratory', 8, 'fa-microscope', 'icon-cyan', 'High precision optics'],
          ['Safety Goggles & Face Shield', 'Laboratory', 25, 'fa-glasses', 'icon-purple', 'Eye & face safety gear'],
          ['Triple Beam Balance Scale', 'Laboratory', 6, 'fa-scale-balanced', 'icon-purple', 'Mechanical mass scale'],
          ['Digital Vernier Caliper', 'Laboratory', 0, 'fa-ruler-combined', 'icon-orange', 'Precision dimension tool'],
          ['Dual-Head Stethoscope', 'Nursing', 15, 'fa-stethoscope', 'icon-orange', 'Heart and lung sound check'],
          ['Manual Blood Pressure Monitor', 'Nursing', 10, 'fa-heart-pulse', 'icon-orange', 'BP cuff with gauge'],
          ['Digital Pulse Oximeter & Thermometer', 'Nursing', 12, 'fa-temperature-three-quarters', 'icon-orange', 'Oxygen & temp monitor'],
          ['Medical Penlight & Reflex Hammer', 'Nursing', 0, 'fa-hand-holding-medical', 'icon-purple', 'Diagnostic reflex kit']
        ];

        const statement = db.prepare(`
          INSERT INTO equipment (name, category, stock, icon, color_class, description)
          VALUES (?, ?, ?, ?, ?, ?)
        `);
        initialItems.forEach((item) => statement.run(item));
        statement.finalize((seedErr) => {
          if (seedErr) console.error('Failed to seed equipment:', seedErr.message);
          else console.log('Seeded initial lab equipment into database.');
        });
      });
    });
  });
}

function initializeRequestsTable() {
  db.get("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'requests'", [], (err, table) => {
    if (err) {
      console.error('Failed to inspect borrowing requests table:', err.message);
      return;
    }

    const createSchema = (callback) => db.run(`
      CREATE TABLE requests (
        request_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student_id TEXT NOT NULL,
        student_name TEXT NOT NULL,
        equipment_id INTEGER,
        item_name TEXT NOT NULL,
        request_date TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending Approval'
          CHECK (status IN ('Pending Approval', 'Approved', 'Rejected', 'Returned Item')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (equipment_id) REFERENCES equipment(id) ON DELETE SET NULL
      )
    `, callback);

    if (!table) {
      createSchema((createErr) => {
        if (createErr) console.error('Failed to create borrowing requests table:', createErr.message);
      });
      return;
    }

    db.all('PRAGMA table_info(requests)', [], (columnsErr, columns) => {
      if (columnsErr) {
        console.error('Failed to inspect borrowing request columns:', columnsErr.message);
        return;
      }
      const existingColumns = new Set(columns.map((column) => column.name));
      const requiredColumns = ['user_id', 'student_id', 'student_name', 'equipment_id', 'item_name', 'request_date', 'status'];
      if (requiredColumns.every((column) => existingColumns.has(column))) return;

      db.serialize(() => {
        db.run('BEGIN IMMEDIATE', (beginErr) => {
          if (beginErr) {
            console.error('Failed to start requests table migration:', beginErr.message);
            return;
          }
          db.run('ALTER TABLE requests RENAME TO requests_legacy', (renameErr) => {
            if (renameErr) {
              console.error('Failed to preserve the old requests table:', renameErr.message);
              db.run('ROLLBACK');
              return;
            }
            createSchema((createErr) => {
              if (createErr) {
                console.error('Failed to create migrated requests table:', createErr.message);
                db.run('ROLLBACK');
                return;
              }
              const hasLegacyColumn = (column) => existingColumns.has(column);
              const studentId = hasLegacyColumn('student_id') ? 'legacy.student_id' : "''";
              const studentName = hasLegacyColumn('student_id')
                ? 'COALESCE(users.full_name, legacy.student_id)'
                : "'Unknown student'";
              const equipmentId = hasLegacyColumn('item_id') ? 'equipment.id' : 'NULL';
              const itemName = hasLegacyColumn('item_id')
                ? "COALESCE(equipment.name, 'Unknown equipment #' || legacy.item_id)"
                : "'Unknown equipment'";
              const requestDate = hasLegacyColumn('request_date') ? "COALESCE(legacy.request_date, datetime('now'))" : "datetime('now')";
              const status = hasLegacyColumn('status')
                ? `CASE WHEN legacy.status IN ('Pending Approval', 'Approved', 'Rejected', 'Returned Item') THEN legacy.status ELSE 'Pending Approval' END`
                : "'Pending Approval'";

              db.run(`
                INSERT INTO requests (user_id, student_id, student_name, equipment_id, item_name, request_date, status)
                SELECT users.id, ${studentId}, ${studentName}, ${equipmentId}, ${itemName}, ${requestDate}, ${status}
                FROM requests_legacy AS legacy
                LEFT JOIN users ON users.student_id = legacy.student_id
                LEFT JOIN equipment ON equipment.id = legacy.item_id
              `, (copyErr) => {
                if (copyErr) {
                  console.error('Failed to migrate existing borrowing requests:', copyErr.message);
                  db.run('ROLLBACK');
                  return;
                }
                db.run('DROP TABLE requests_legacy', (dropErr) => {
                  if (dropErr) {
                    console.error('Failed to finish requests table migration:', dropErr.message);
                    db.run('ROLLBACK');
                    return;
                  }
                  db.run('COMMIT', (commitErr) => {
                    if (commitErr) {
                      console.error('Failed to commit requests table migration:', commitErr.message);
                      db.run('ROLLBACK');
                    } else {
                      console.log('Migrated existing borrowing requests table.');
                    }
                  });
                });
              });
            });
          });
        });
      });
    });
  });
}

initializeDatabase();

app.post('/api/register', async (req, res) => {
  const { full_name, email, studentId, password } = req.body || {};
  if (typeof studentId !== 'string' || studentId.trim().length < 2 || studentId.trim().length > 64) {
    return res.status(400).json({ error: 'Student ID must be between 2 and 64 characters.' });
  }
  if (typeof full_name !== 'string' || full_name.trim().length < 3 || full_name.trim().length > 100) {
    return res.status(400).json({ error: 'Full name must be between 3 and 100 characters.' });
  }
  if (typeof email !== 'string' || email.trim().length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (typeof password !== 'string' || password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ error: 'Password must be at least 8 characters and no more than 72 bytes.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    db.run(
      `INSERT INTO users (student_id, email, full_name, password, role)
       VALUES (?, ?, ?, ?, 'student')`,
      [studentId.trim(), email.trim().toLowerCase(), full_name.trim(), passwordHash],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'This Student ID or Email is already registered.' });
          }
          console.error('Failed to register user:', err.message);
          return res.status(500).json({ error: 'Registration failed. Please try again later.' });
        }
        createSession(this.lastID, res, {
          fullName: full_name.trim(),
          studentId: studentId.trim(),
          role: 'student'
        });
      }
    );
  } catch (err) {
    console.error('Failed to hash registration password:', err.message);
    res.status(500).json({ error: 'Registration failed. Please try again later.' });
  }
});

app.post('/api/login', (req, res) => {
  const { studentId, password, role } = req.body || {};
  if (typeof studentId !== 'string' || !studentId.trim() ||
      typeof password !== 'string' || !password ||
      !['student', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Enter your ID, password, and account type.' });
  }

  db.get(
    `SELECT id, student_id, full_name, password, role
     FROM users
     WHERE student_id = ? COLLATE NOCASE OR email = ? COLLATE NOCASE`,
    [studentId.trim(), studentId.trim().toLowerCase()],
    async (err, user) => {
      if (err) {
        console.error('Failed to look up login account:', err.message);
        return res.status(500).json({ error: 'Login failed. Please try again later.' });
      }
      if (!user) {
        return res.status(401).json({ error: 'Invalid ID or password.' });
      }

      try {
        const isBcryptHash = /^\$2[aby]\$/.test(user.password);
        const passwordMatches = isBcryptHash
          ? await bcrypt.compare(password, user.password)
          : password === user.password;

        if (!passwordMatches) {
          return res.status(401).json({ error: 'Invalid ID or password.' });
        }
        if (role !== user.role) {
          return res.status(403).json({ error: 'This account cannot use the selected portal.' });
        }

        if (!isBcryptHash) {
          const passwordHash = await bcrypt.hash(password, 12);
          db.run('UPDATE users SET password = ? WHERE id = ?', [passwordHash, user.id], (updateErr) => {
            if (updateErr) {
              console.error('Failed to upgrade legacy password hash:', updateErr.message);
              return res.status(500).json({ error: 'Login failed. Please try again later.' });
            }
            createSession(user.id, res, {
              fullName: user.full_name,
              studentId: user.student_id,
              role: user.role
            });
          });
          return;
        }

        createSession(user.id, res, {
          fullName: user.full_name,
          studentId: user.student_id,
          role: user.role
        });
      } catch (hashErr) {
        console.error('Failed to verify login password:', hashErr.message);
        res.status(500).json({ error: 'Login failed. Please try again later.' });
      }
    }
  );
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    user: {
      fullName: req.user.full_name,
      studentId: req.user.student_id,
      role: req.user.role
    }
  });
});

app.post('/api/logout', (req, res) => {
  const token = getCookie(req, SESSION_COOKIE);
  clearSessionCookie(res);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return res.json({ message: 'Logged out.' });
  }

  db.run('DELETE FROM sessions WHERE token_hash = ?', [tokenHash(token)], (err) => {
    if (err) {
      console.error('Failed to delete login session:', err.message);
      return res.status(500).json({ error: 'Could not log out. Please try again.' });
    }
    res.json({ message: 'Logged out.' });
  });
});

app.get('/api/requests', requireAuth, (req, res) => {
  const query = req.user.role === 'admin'
    ? `SELECT request_id AS requestId, student_id AS id, student_name AS student,
              item_name AS item, request_date AS date, status
       FROM requests ORDER BY request_id DESC`
    : `SELECT request_id AS requestId, student_id AS id, student_name AS student,
              item_name AS item, request_date AS date, status
       FROM requests WHERE user_id = ? ORDER BY request_id DESC`;
  const params = req.user.role === 'admin' ? [] : [req.user.id];

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Failed to retrieve borrowing requests:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve borrowing requests.' });
    }
    res.json(rows);
  });
});

app.post('/api/requests', requireAuth, (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Only student accounts can request equipment.' });
  }
  const equipmentId = req.body && req.body.equipmentId;
  if (!Number.isSafeInteger(equipmentId) || equipmentId < 1) {
    return res.status(400).json({ error: 'Select a valid equipment item.' });
  }

  db.get('SELECT id, name, stock FROM equipment WHERE id = ?', [equipmentId], (err, item) => {
    if (err) {
      console.error('Failed to look up requested equipment:', err.message);
      return res.status(500).json({ error: 'Could not submit the borrowing request.' });
    }
    if (!item) return res.status(404).json({ error: 'Equipment item not found.' });
    if (item.stock < 1) return res.status(409).json({ error: 'This equipment is currently unavailable.' });

    db.run(
      `INSERT INTO requests (user_id, student_id, student_name, equipment_id, item_name, request_date)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.id, req.user.student_id, req.user.full_name, item.id, item.name, new Date().toISOString()],
      function (insertErr) {
        if (insertErr) {
          console.error('Failed to save borrowing request:', insertErr.message);
          return res.status(500).json({ error: 'Could not save the borrowing request.' });
        }
        res.status(201).json({ message: 'Borrow request sent for approval.', requestId: this.lastID });
      }
    );
  });
});

app.put('/api/requests/:id/status', requireAuth, requireAdmin, async (req, res) => {
  const requestId = Number(req.params.id);
  const { status } = req.body || {};
  if (!Number.isSafeInteger(requestId) || requestId < 1 || !['Approved', 'Rejected'].includes(status)) {
    return res.status(400).json({ error: 'Choose a valid request and status.' });
  }

  try {
    const updated = await runTransaction(async (run) => {
      if (status === 'Approved') {
        const result = await run(
          `UPDATE equipment
           SET stock = stock - 1
           WHERE id = (
             SELECT equipment_id FROM requests
             WHERE request_id = ? AND status = 'Pending Approval'
           ) AND stock > 0`,
          [requestId]
        );
        if (result.changes === 0) {
          const request = await new Promise((resolve, reject) => {
            db.get('SELECT status, equipment_id FROM requests WHERE request_id = ?', [requestId],
              (err, row) => err ? reject(err) : resolve(row));
          });
          if (!request) return { error: 'Borrow request not found.', statusCode: 404 };
          if (request.status !== 'Pending Approval') return { error: 'This request has already been processed.', statusCode: 409 };
          return { error: 'This equipment is no longer available.', statusCode: 409 };
        }
      }

      const change = await run(
        `UPDATE requests SET status = ?
         WHERE request_id = ? AND status = 'Pending Approval'`,
        [status, requestId]
      );
      if (change.changes === 0) {
        return { error: 'Borrow request not found or already processed.', statusCode: 409 };
      }
      return { message: `Borrow request ${status.toLowerCase()}.` };
    });

    if (updated.error) return res.status(updated.statusCode).json({ error: updated.error });
    res.json({ message: updated.message });
  } catch (err) {
    console.error('Failed to update borrowing request:', err.message);
    res.status(500).json({ error: 'Failed to update borrowing request.' });
  }
});

app.post('/api/requests/:id/return', requireAuth, async (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Only students can return their borrowed equipment.' });
  }
  const requestId = Number(req.params.id);
  if (!Number.isSafeInteger(requestId) || requestId < 1) {
    return res.status(400).json({ error: 'Request ID must be a positive integer.' });
  }

  try {
    const result = await runTransaction(async (run) => {
      const request = await new Promise((resolve, reject) => {
        db.get(
          `SELECT equipment_id, status FROM requests
           WHERE request_id = ? AND user_id = ?`,
          [requestId, req.user.id],
          (err, row) => err ? reject(err) : resolve(row)
        );
      });
      if (!request) return { error: 'Borrow request not found.', statusCode: 404 };
      if (request.status !== 'Approved') return { error: 'Only approved requests can be returned.', statusCode: 409 };

      if (request.equipment_id !== null) {
        const stockResult = await run('UPDATE equipment SET stock = stock + 1 WHERE id = ?', [request.equipment_id]);
        if (stockResult.changes === 0) {
          return { error: 'The equipment record no longer exists.', statusCode: 409 };
        }
      }

      const update = await run(
        `UPDATE requests SET status = 'Returned Item'
         WHERE request_id = ? AND user_id = ? AND status = 'Approved'`,
        [requestId, req.user.id]
      );
      if (update.changes === 0) return { error: 'This request has already been processed.', statusCode: 409 };
      return { message: 'Item marked as returned.' };
    });

    if (result.error) return res.status(result.statusCode).json({ error: result.error });
    res.json({ message: result.message });
  } catch (err) {
    console.error('Failed to return borrowed equipment:', err.message);
    res.status(500).json({ error: 'Failed to return borrowed equipment.' });
  }
});

app.get('/api/equipment', (req, res) => {
  db.all('SELECT * FROM equipment', [], (err, rows) => {
    if (err) {
      console.error('Failed to retrieve lab equipment:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve lab equipment.' });
    }
    res.json(rows);
  });
});

app.put('/api/equipment/:id', requireAuth, requireAdmin, (req, res) => {
  const equipmentId = Number(req.params.id);
  const { stock } = req.body || {};
  if (!Number.isSafeInteger(equipmentId) || equipmentId < 1 ||
      !Number.isSafeInteger(stock) || stock < 0) {
    return res.status(400).json({ error: 'Equipment ID and stock must be valid non-negative integers.' });
  }

  db.run('UPDATE equipment SET stock = ? WHERE id = ?', [stock, equipmentId], function (err) {
    if (err) {
      console.error('Failed to update equipment stock:', err.message);
      return res.status(500).json({ error: 'Failed to update equipment quantity.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Equipment item not found.' });
    }
    res.json({ message: 'Equipment stock updated successfully!' });
  });
});

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  db.all('SELECT id, student_id, email, full_name, role FROM users', [], (err, rows) => {
    if (err) {
      console.error('Failed to retrieve registered users:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve registered users.' });
    }
    res.json(rows);
  });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isSafeInteger(userId) || userId < 1) {
    return res.status(400).json({ error: 'User ID must be a positive integer.' });
  }

  db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error('Failed to look up user for deletion:', err.message);
      return res.status(500).json({ error: 'Failed to delete user account.' });
    }
    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }
    if (user.role === 'admin') {
      return res.status(400).json({ error: 'System Administrator accounts cannot be deleted.' });
    }

    db.run('DELETE FROM users WHERE id = ?', [userId], function (deleteErr) {
      if (deleteErr) {
        console.error('Failed to delete user account:', deleteErr.message);
        return res.status(500).json({ error: 'Failed to delete user account.' });
      }
      db.run('DELETE FROM sessions WHERE user_id = ?', [userId], (sessionErr) => {
        if (sessionErr) {
          console.error('Failed to revoke deleted user sessions:', sessionErr.message);
          return res.status(500).json({ error: 'Account deleted, but active sessions could not be revoked.' });
        }
        res.json({ message: 'User account deleted successfully!' });
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
