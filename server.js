const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
console.log('Environment:', process.env.NODE_ENV);
console.log('DB Host:', process.env.DB_HOST || 'Using Render DB URL');

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs').promises;
const fsSync = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Add error handler for path-to-regexp at the very top
process.on('uncaughtException', (err) => {
  if (err.message.includes('path-to-regexp')) {
    console.error('Path-to-regexp error:', err);
    process.exit(1);
  }
});

// Configuration constants
const CONFIG = {
  JWT_EXPIRY: '24h',
  BCRYPT_ROUNDS: 12,
  FILE_SIZE_LIMIT: 5 * 1024 * 1024, // 5MB
  ALLOWED_FILE_TYPES: ['image/jpeg', 'image/png', 'application/pdf'],
  UPLOAD_DIR: path.join(__dirname, 'tmp_uploads')
};

// Database configuration
const getDatabaseConfig = () => {
  if (process.env.INTERNAL_DATABASE_URL) {
    return {
      connectionString: process.env.INTERNAL_DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    };
  }
  return {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'task_manager',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'your_local_password',
    ssl: false
  };
};

const pool = new Pool(getDatabaseConfig());

// ================== MIDDLEWARE SETUP ================== //
// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(CONFIG.UPLOAD_DIR));

// File upload configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      await fs.access(CONFIG.UPLOAD_DIR);
    } catch {
      await fs.mkdir(CONFIG.UPLOAD_DIR, { recursive: true });
    }
    cb(null, CONFIG.UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    const sanitizedOriginalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
    const extension = path.extname(sanitizedOriginalName);
    cb(null, `${uniqueSuffix}${extension}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: CONFIG.FILE_SIZE_LIMIT,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (CONFIG.ALLOWED_FILE_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, and PDF files are allowed.'));
    }
  }
});

// ================== HELPER FUNCTIONS ================== //
// Database initialization
const initializeDatabase = async () => {
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      const client = await pool.connect();
      await client.query('SELECT NOW()');
      client.release();
      console.log('✅ Connected to PostgreSQL database');
      break;
    } catch (error) {
      retries++;
      console.log(`🔄 Database connection attempt ${retries}/${maxRetries} failed:`, error.message);
      if (retries === maxRetries) {
        throw new Error('❌ Failed to connect to database after maximum retries');
      }
      await new Promise(resolve => setTimeout(resolve, 2000 * retries));
    }
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'cancelled')),
        priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high')),
        attachment_path VARCHAR(500),
        attachment_filename VARCHAR(255),
        due_date TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('❌ Database schema initialization error:', error);
    throw error;
  }
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Validation middleware
const validateRequired = (fields) => (req, res, next) => {
  const missing = fields.filter(field => !req.body[field]);
  if (missing.length) {
    return res.status(400).json({
      error: `Missing required fields: ${missing.join(', ')}`
    });
  }
  next();
};

// ================== ROUTE INITIALIZATION ================== //
const initRoutes = () => {
  // Health check
  app.get('/health', (req, res) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'task-manager-api'
    });
  });

  // Serve frontend
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  // API routes using Router
  const apiRouter = express.Router();
  
  // Apply rate limiting
  apiRouter.use(generalLimiter);
  apiRouter.use(['/auth/login', '/auth/register'], authLimiter);

  // API documentation
  apiRouter.get('/', (req, res) => {
    res.json({
      name: 'Task Manager API',
      version: '1.0.0',
      status: 'running',
      message: 'Welcome to the Task Manager API',
      endpoints: {
        health: '/health',
        api_health: '/api/health',
        authentication: {
          login: '/api/auth/login',
          register: '/api/auth/register'
        },
        tasks: {
          list: 'GET /api/tasks',
          create: 'POST /api/tasks',
          get: 'GET /api/tasks/:id',
          update: 'PUT /api/tasks/:id',
          delete: 'DELETE /api/tasks/:id'
        }
      },
      documentation: 'Use the endpoints above to interact with the API',
      timestamp: new Date().toISOString()
    });
  });

  // Authentication routes
  apiRouter.post('/auth/register', validateRequired(['username', 'email', 'password']), async (req, res) => {
    try {
      const { username, email, password } = req.body;
      const passwordHash = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);
      const result = await pool.query(
        `INSERT INTO users (username, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, username, email, created_at`,
        [username.toLowerCase(), email.toLowerCase(), passwordHash]
      );
      const user = result.rows[0];
      const accessToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: CONFIG.JWT_EXPIRY }
      );
      res.status(201).json({ success: true, accessToken, user });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  apiRouter.post('/auth/login', validateRequired(['username', 'password']), async (req, res) => {
    try {
      const { username, password } = req.body;
      const result = await pool.query(
        'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
        [username]
      );
      if (result.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const user = result.rows[0];
      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const accessToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: CONFIG.JWT_EXPIRY }
      );
      res.json({ success: true, accessToken, user });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  // Task routes
  apiRouter.get('/tasks', authenticateToken, async (req, res) => {
    try {
      const result = await pool.query(
        'SELECT * FROM tasks WHERE user_id = $1',
        [req.user.id]
      );
      res.json({ success: true, tasks: result.rows });
    } catch (error) {
      console.error('Failed to fetch tasks:', error);
      res.status(500).json({ error: 'Failed to fetch tasks' });
    }
  });

  // Updated task creation route with proper validation
  apiRouter.post('/tasks', authenticateToken, upload.single('attachment'), validateRequired(['title']), async (req, res) => {
    try {
      const { title, description, status = 'pending', priority = 'medium', due_date } = req.body;
      
      // Validate status against allowed values
      const allowedStatuses = ['pending', 'in_progress', 'completed', 'cancelled'];
      if (status && !allowedStatuses.includes(status)) {
        return res.status(400).json({ 
          error: `Invalid status. Must be one of: ${allowedStatuses.join(', ')}`,
          code: 'INVALID_STATUS'
        });
      }

      // Validate priority against allowed values
      const allowedPriorities = ['low', 'medium', 'high'];
      if (priority && !allowedPriorities.includes(priority)) {
        return res.status(400).json({ 
          error: `Invalid priority. Must be one of: ${allowedPriorities.join(', ')}`,
          code: 'INVALID_PRIORITY'
        });
      }

      // Handle file upload validation
      if (req.file) {
        if (!CONFIG.ALLOWED_FILE_TYPES.includes(req.file.mimetype)) {
          await fs.unlink(req.file.path); // Clean up the uploaded file
          return res.status(400).json({
            error: 'Invalid file type. Only JPEG, PNG, and PDF files are allowed.',
            code: 'INVALID_FILE_TYPE'
          });
        }
      }

      const result = await pool.query(
        `INSERT INTO tasks (title, description, status, priority, attachment_path, attachment_filename, due_date, user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          title.trim(),
          description?.trim(),
          status,
          priority,
          req.file?.path,
          req.file?.originalname,
          due_date,
          req.user.id
        ]
      );
      
      res.status(201).json({ 
        success: true, 
        task: result.rows[0] 
      });
    } catch (error) {
      console.error('Failed to create task:', error);
      
      // Clean up uploaded file if error occurred
      if (req.file) {
        try {
          await fs.unlink(req.file.path);
        } catch (cleanupError) {
          console.error('Failed to clean up uploaded file:', cleanupError);
        }
      }

      if (error.code === '23514' && error.constraint === 'tasks_status_check') {
        return res.status(400).json({
          error: 'Invalid task status. Allowed values: pending, in_progress, completed, cancelled',
          code: 'INVALID_STATUS_VALUE'
        });
      }

      res.status(500).json({ 
        error: 'Failed to create task',
        code: 'TASK_CREATION_FAILED'
      });
    }
  });

  // Mount API router
  app.use('/api', apiRouter);

  // SPA fallback
  app.get('*', (req, res) => {
    if (req.accepts('html')) {
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
    res.status(404).json({ error: 'Not found' });
  });
};

// ================== SERVER INITIALIZATION ================== //
const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Initialize routes
    initRoutes();

    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
      console.log(`🏥 Health check: http://0.0.0.0:${PORT}/health`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();