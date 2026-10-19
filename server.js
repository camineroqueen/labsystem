const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Connect to SQLite Database
const db = new sqlite3.Database('./labconnect.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database: labconnect.db');
  }
});

// Initialize Table Schema
db.serialize(() => {
  // Users Table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      full_name TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'student'
    )
  `);

  // Equipment Inventory Table (Auto-rebuilds outdated schema safely)
  db.run(`DROP TABLE IF EXISTS equipment`, (err) => {
    if (err) {
      console.error('Error resetting equipment table:', err.message);
      return;
    }

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
    `, () => {
      // Seed initial equipment
      db.get(`SELECT COUNT(*) as count FROM equipment`, [], (err, row) => {
        if (!err && row.count === 0) {
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

          const stmt = db.prepare(`INSERT INTO equipment (name, category, stock, icon, color_class, description) VALUES (?, ?, ?, ?, ?, ?)`);
          initialItems.forEach(item => stmt.run(item));
          stmt.finalize();
          console.log('Seeded initial lab equipment into database.');
        }
      });
    });
  });
});

// Registration API Endpoint
app.post('/api/register', (req, res) => {
  const { full_name, email, studentId, password } = req.body;

  if (!studentId || studentId.trim() === '') {
    return res.status(400).json({ error: 'Student ID number is required.' });
  }
  if (!full_name || full_name.trim() === '') {
    return res.status(400).json({ error: 'Official full name is required.' });
  }
  if (!password || password.trim() === '') {
    return res.status(400).json({ error: 'Password is required.' });
  }

  const query = `
    INSERT INTO users (student_id, email, full_name, password, role) 
    VALUES (?, ?, ?, ?, 'student')
  `;

  db.run(query, [studentId.trim(), email ? email.trim() : null, full_name.trim(), password], function (err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'This Student ID or Email is already registered in the system.' });
      }
      if (err.message.includes('NOT NULL constraint failed')) {
        return res.status(400).json({ error: 'Please fill out all required fields before submitting.' });
      }
      return res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
    }

    res.json({ message: 'Registration successful!', userId: this.lastID });
  });
});

// Login API Endpoint
app.post('/api/login', (req, res) => {
  const { studentId, password, role } = req.body;

  if (!studentId || !password) {
    return res.status(400).json({ error: 'Please enter both your credentials and password.' });
  }

  const query = `SELECT * FROM users WHERE student_id = ? AND password = ?`;

  db.get(query, [studentId.trim(), password], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'An unexpected error occurred.' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid Student ID or Password. Please check your details.' });
    }

    if (role === 'admin' && user.role !== 'admin') {
      return res.status(403).json({ error: 'Access Denied: This account does not have Administrator privileges.' });
    }

    res.json({ 
      message: 'Login successful!', 
      user: { fullName: user.full_name, studentId: user.student_id, role: user.role } 
    });
  });
});

// GET ALL EQUIPMENT (PUBLIC)
app.get('/api/equipment', (req, res) => {
  db.all(`SELECT * FROM equipment`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve lab equipment.' });
    }
    res.json(rows);
  });
});

// UPDATE EQUIPMENT STOCK REAL-TIME (ADMIN FEATURE)
app.put('/api/equipment/:id', (req, res) => {
  const { stock } = req.body;
  const equipmentId = req.params.id;

  if (stock < 0 || isNaN(stock)) {
    return res.status(400).json({ error: 'Stock quantity must be a valid positive number.' });
  }

  db.run(`UPDATE equipment SET stock = ? WHERE id = ?`, [stock, equipmentId], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update equipment quantity.' });
    }
    res.json({ message: 'Equipment stock updated successfully!' });
  });
});

// GET ALL USERS (ADMIN FEATURE)
app.get('/api/users', (req, res) => {
  db.all(`SELECT id, student_id, email, full_name, role FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve registered users.' });
    }
    res.json(rows);
  });
});

// DELETE A USER ACCOUNT (ADMIN FEATURE)
app.delete('/api/users/:id', (req, res) => {
  const userId = req.params.id;

  db.get(`SELECT role FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User account not found.' });
    }
    if (user.role === 'admin') {
      return res.status(400).json({ error: 'System Administrator accounts cannot be deleted.' });
    }

    db.run(`DELETE FROM users WHERE id = ?`, [userId], function (err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to delete user account.' });
      }
      res.json({ message: 'User account deleted successfully!' });
    });
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});