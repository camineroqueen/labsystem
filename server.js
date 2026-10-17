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
      
      console.error('Internal Server Error:', err.message);
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
      console.error('Login Query Error:', err.message);
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

// GET ALL USERS (ADMIN FEATURE)
app.get('/api/users', (req, res) => {
  db.all(`SELECT id, student_id, email, full_name, role FROM users`, [], (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve registered users.' });
    }
    res.json(rows);
  });
});

// DELETE A USER ACCOUNT (ADMIN FEATURE)
app.delete('/api/users/:id', (req, res) => {
  const userId = req.params.id;

  // Prevent accidental deletion of main system administrator
  db.get(`SELECT role FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User account not found.' });
    }
    if (user.role === 'admin') {
      return res.status(400).json({ error: 'System Administrator accounts cannot be deleted.' });
    }

    db.run(`DELETE FROM users WHERE id = ?`, [userId], function (err) {
      if (err) {
        console.error('Error deleting user:', err.message);
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