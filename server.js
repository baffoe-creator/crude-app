require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Database Setup - UPDATED FOR RENDER COMPATIBILITY
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:your_local_password@localhost:5432/task_manager',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Test connection and initialize tables
(async () => {
  try {
    await pool.query('SELECT NOW()');
    console.log('Connected to PostgreSQL database');

    // Initialize schema
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        description TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        attachment_path VARCHAR(255),
        due_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER NOT NULL REFERENCES users(id)
      )`);

    console.log('Database tables initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
    process.exit(1);
  }
})();

// Middleware (unchanged)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// File upload configuration (unchanged)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync('uploads')) {
      fs.mkdirSync('uploads');
    }
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, and PDF are allowed.'));
    }
  }
});

// Authentication middleware (unchanged)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Updated Routes with PostgreSQL

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (userCheck.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password and create user
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username',
      [username, email, passwordHash]
    );

    // Generate JWT
    const user = newUser.rows[0];
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

    res.status(201).json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const userResult = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Updated Task Routes

app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/tasks', authenticateToken, upload.single('attachment'), async (req, res) => {
  try {
    const { title, description, status, due_date } = req.body;
    const attachment_path = req.file ? req.file.path : null;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const newTask = await pool.query(
      'INSERT INTO tasks (title, description, status, attachment_path, due_date, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [title, description, status || 'pending', attachment_path, due_date, req.user.id]
    );

    res.status(201).json(newTask.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (task.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json(task.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/tasks/:id', authenticateToken, upload.single('attachment'), async (req, res) => {
  try {
    const { title, description, status, due_date } = req.body;
    const attachment_path = req.file ? req.file.path : null;

    // Get existing task
    const existingTask = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (existingTask.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    const task = existingTask.rows[0];

    // Delete old file if new one uploaded
    if (req.file && task.attachment_path) {
      fs.unlink(task.attachment_path, (err) => {
        if (err) console.error('Error deleting old file:', err);
      });
    }

    const updatedTask = await pool.query(
      'UPDATE tasks SET title = $1, description = $2, status = $3, attachment_path = $4, due_date = $5 WHERE id = $6 AND user_id = $7 RETURNING *',
      [
        title || task.title,
        description !== undefined ? description : task.description,
        status || task.status,
        attachment_path || task.attachment_path,
        due_date || task.due_date,
        req.params.id,
        req.user.id
      ]
    );

    res.json(updatedTask.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    // Get task first to handle attachment cleanup
    const task = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (task.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    // Delete attachment if exists
    if (task.rows[0].attachment_path) {
      fs.unlink(task.rows[0].attachment_path, (err) => {
        if (err) console.error('Error deleting file:', err);
      });
    }

    await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    res.sendStatus(204);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Start server (unchanged)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});