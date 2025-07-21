require('dotenv').config(); // Load environment variables first
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration constants
const CONFIG = {
  JWT_EXPIRY: '24h',
  BCRYPT_ROUNDS: 12,
  FILE_SIZE_LIMIT: 5 * 1024 * 1024, // 5MB
  ALLOWED_FILE_TYPES: ['image/jpeg', 'image/png', 'application/pdf'],
  UPLOAD_DIR: path.join(__dirname, 'tmp_uploads') // Render-compatible ephemeral storage
};

// Database configuration for Render deployment
const getDatabaseConfig = () => {
  if (process.env.INTERNAL_DATABASE_URL) {
    // Production/Render configuration
    return {
      connectionString: process.env.INTERNAL_DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    };
  }

  // Local development configuration
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

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false, // Needed for file uploads
  contentSecurityPolicy: false // Adjust based on your frontend needs
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // More lenient for production
  message: { error: 'Too many authentication attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Apply rate limiting
app.use('/api/', generalLimiter);
app.use(['/api/auth/login', '/api/auth/register'], authLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Render-required health check endpoint (must be at root level)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'task-manager-api'
  });
});

// Static file serving for ephemeral uploads
app.use('/uploads', express.static(CONFIG.UPLOAD_DIR));

// File upload configuration optimized for Render's ephemeral storage
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      // Ensure upload directory exists (Render's ephemeral storage)
      await fs.access(CONFIG.UPLOAD_DIR);
    } catch {
      await fs.mkdir(CONFIG.UPLOAD_DIR, { recursive: true });
    }
    cb(null, CONFIG.UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Create unique filename with original extension
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
    files: 1 // Only allow single file upload
  },
  fileFilter: (req, file, cb) => {
    if (CONFIG.ALLOWED_FILE_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, and PDF files are allowed.'));
    }
  }
});

// Database initialization with better error handling
const initializeDatabase = async () => {
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      // Test connection with timeout
      const client = await pool.connect();
      await client.query('SELECT NOW()');
      client.release();

      console.log('✅ Connected to PostgreSQL database');
      break;
    } catch (error) {
      retries++;
      console.log(`🔄 Database connection attempt ${retries}/${maxRetries} failed:`, error.message);

      if (retries === maxRetries) {
        console.error('❌ Failed to connect to database after maximum retries');
        process.exit(1);
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 2000 * retries));
    }
  }

  try {
    // Create users table with improved schema
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

    // Create tasks table with improved schema
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

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
      CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
      CREATE INDEX IF NOT EXISTS idx_tasks_due_date ON tasks(due_date);
      CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
    `);

    // Create function to auto-update updated_at timestamp
    await pool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Create triggers for auto-updating updated_at
    await pool.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
      FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

      DROP TRIGGER IF EXISTS update_tasks_updated_at ON tasks;
      CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON tasks
      FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    `);

    console.log('✅ Database tables and indexes initialized');
  } catch (error) {
    console.error('❌ Database schema initialization error:', error);
    process.exit(1);
  }
};

// Enhanced authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      code: 'TOKEN_MISSING'
    });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      const errorCode = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID';
      return res.status(403).json({
        error: 'Invalid or expired token',
        code: errorCode
      });
    }
    req.user = user;
    next();
  });
};

// Validation middleware
const validateRequired = (fields) => (req, res, next) => {
  const missing = fields.filter(field => {
    const value = req.body[field];
    return value === undefined || value === null || value === '';
  });

  if (missing.length > 0) {
    return res.status(400).json({
      error: `Missing required fields: ${missing.join(', ')}`,
      code: 'VALIDATION_ERROR',
      missing_fields: missing
    });
  }
  next();
};

// Enhanced validation functions
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
};

const validatePassword = (password) => {
  return password && password.length >= 6 && password.length <= 128;
};

const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_-]+$/;
  return username && username.length >= 3 && username.length <= 50 && usernameRegex.test(username);
};

// Enhanced error handling
const handleDatabaseError = (error, res, customMessage = 'Database error') => {
  console.error('Database error:', {
    message: error.message,
    code: error.code,
    detail: error.detail,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
  });

  // Handle specific PostgreSQL error codes
  switch (error.code) {
    case '23505': // Unique violation
      return res.status(409).json({
        error: 'Resource already exists',
        code: 'DUPLICATE_ENTRY'
      });
    case '23503': // Foreign key violation
      return res.status(400).json({
        error: 'Invalid reference',
        code: 'INVALID_REFERENCE'
      });
    case '22001': // String data too long
      return res.status(400).json({
        error: 'Data too long for field',
        code: 'DATA_TOO_LONG'
      });
    case '23514': // Check constraint violation
      return res.status(400).json({
        error: 'Invalid data value',
        code: 'CONSTRAINT_VIOLATION'
      });
    default:
      return res.status(500).json({
        error: customMessage,
        code: 'DATABASE_ERROR'
      });
  }
};

// Safe file operations for ephemeral storage
const safeDeleteFile = async (filePath) => {
  try {
    await fs.access(filePath);
    await fs.unlink(filePath);
    console.log(`🗑️ Deleted file: ${filePath}`);
  } catch (error) {
    console.warn(`⚠️ Failed to delete file ${filePath}:`, error.message);
  }
};

// Authentication routes
app.post('/api/auth/register',
  validateRequired(['username', 'email', 'password']),
  async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // Enhanced input validation
      if (!validateUsername(username)) {
        return res.status(400).json({
          error: 'Username must be 3-50 characters and contain only letters, numbers, hyphens, and underscores',
          code: 'INVALID_USERNAME'
        });
      }

      if (!validateEmail(email)) {
        return res.status(400).json({
          error: 'Invalid email format',
          code: 'INVALID_EMAIL'
        });
      }

      if (!validatePassword(password)) {
        return res.status(400).json({
          error: 'Password must be 6-128 characters long',
          code: 'INVALID_PASSWORD'
        });
      }

      // Check if user exists
      const existingUser = await pool.query(
        'SELECT id FROM users WHERE username = $1 OR email = $2',
        [username.toLowerCase(), email.toLowerCase()]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({
          error: 'Username or email already exists',
          code: 'USER_EXISTS'
        });
      }

      // Hash password and create user
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

      res.status(201).json({
        success: true,
        accessToken,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          created_at: user.created_at
        }
      });
    } catch (error) {
      handleDatabaseError(error, res, 'Registration failed');
    }
  }
);

app.post('/api/auth/login',
  validateRequired(['username', 'password']),
  async (req, res) => {
    try {
      const { username, password } = req.body;

      // Find user (case-insensitive)
      const result = await pool.query(
        'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
        [username]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      const user = result.rows[0];
      const validPassword = await bcrypt.compare(password, user.password_hash);

      if (!validPassword) {
        return res.status(401).json({
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      // Generate JWT
      const accessToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: CONFIG.JWT_EXPIRY }
      );

      res.json({
        success: true,
        accessToken,
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        }
      });
    } catch (error) {
      handleDatabaseError(error, res, 'Login failed');
    }
  }
);

// Enhanced task routes
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const {
      status,
      priority,
      page = 1,
      limit = 10,
      sort = 'created_at',
      order = 'DESC',
      search
    } = req.query;

    let query = 'SELECT * FROM tasks WHERE user_id = $1';
    const params = [req.user.id];
    let paramIndex = 2;

    // Add search functionality
    if (search) {
      query += ` AND (title ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    // Add filters
    if (status && ['pending', 'in_progress', 'completed', 'cancelled'].includes(status)) {
      query += ` AND status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    if (priority && ['low', 'medium', 'high'].includes(priority)) {
      query += ` AND priority = $${paramIndex}`;
      params.push(priority);
      paramIndex++;
    }

    // Add sorting
    const validSortFields = ['created_at', 'updated_at', 'due_date', 'title', 'priority', 'status'];
    const sortField = validSortFields.includes(sort) ? sort : 'created_at';
    const sortOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    query += ` ORDER BY ${sortField} ${sortOrder}`;

    // Add pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Cap at 100
    const offset = (pageNum - 1) * limitNum;

    query += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limitNum, offset);

    const result = await pool.query(query, params);

    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) FROM tasks WHERE user_id = $1';
    const countParams = [req.user.id];

    if (search) {
      countQuery += ' AND (title ILIKE $2 OR description ILIKE $2)';
      countParams.push(`%${search}%`);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);

    res.json({
      success: true,
      tasks: result.rows,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        pages: Math.ceil(total / limitNum),
        hasNext: pageNum * limitNum < total,
        hasPrev: pageNum > 1
      }
    });
  } catch (error) {
    handleDatabaseError(error, res, 'Failed to fetch tasks');
  }
});

app.post('/api/tasks',
  authenticateToken,
  upload.single('attachment'),
  validateRequired(['title']),
  async (req, res) => {
    try {
      const { title, description, status = 'pending', priority = 'medium', due_date } = req.body;
      const attachment_path = req.file ? req.file.path : null;
      const attachment_filename = req.file ? req.file.originalname : null;

      // Validate inputs
      if (title.length > 255) {
        return res.status(400).json({
          error: 'Title must not exceed 255 characters',
          code: 'TITLE_TOO_LONG'
        });
      }

      if (!['pending', 'in_progress', 'completed', 'cancelled'].includes(status)) {
        return res.status(400).json({
          error: 'Invalid status. Must be: pending, in_progress, completed, or cancelled',
          code: 'INVALID_STATUS'
        });
      }

      if (!['low', 'medium', 'high'].includes(priority)) {
        return res.status(400).json({
          error: 'Invalid priority. Must be: low, medium, or high',
          code: 'INVALID_PRIORITY'
        });
      }

      const result = await pool.query(
        `INSERT INTO tasks (title, description, status, priority, attachment_path, attachment_filename, due_date, user_id)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *`,
        [title.trim(), description?.trim(), status, priority, attachment_path, attachment_filename, due_date, req.user.id]
      );

      res.status(201).json({
        success: true,
        task: result.rows[0]
      });
    } catch (error) {
      handleDatabaseError(error, res, 'Failed to create task');
    }
  }
);

app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);

    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        error: 'Invalid task ID',
        code: 'INVALID_TASK_ID'
      });
    }

    const result = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Task not found',
        code: 'TASK_NOT_FOUND'
      });
    }

    res.json({
      success: true,
      task: result.rows[0]
    });
  } catch (error) {
    handleDatabaseError(error, res, 'Failed to fetch task');
  }
});

app.put('/api/tasks/:id',
  authenticateToken,
  upload.single('attachment'),
  async (req, res) => {
    try {
      const taskId = parseInt(req.params.id);

      if (isNaN(taskId) || taskId <= 0) {
        return res.status(400).json({
          error: 'Invalid task ID',
          code: 'INVALID_TASK_ID'
        });
      }

      // Get existing task
      const existingTask = await pool.query(
        'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
        [taskId, req.user.id]
      );

      if (existingTask.rows.length === 0) {
        return res.status(404).json({
          error: 'Task not found',
          code: 'TASK_NOT_FOUND'
        });
      }

      const task = existingTask.rows[0];
      const { title, description, status, priority, due_date } = req.body;

      // Validate inputs if provided
      if (title !== undefined && (typeof title !== 'string' || title.length === 0 || title.length > 255)) {
        return res.status(400).json({
          error: 'Title must be a non-empty string with max 255 characters',
          code: 'INVALID_TITLE'
        });
      }

      if (status && !['pending', 'in_progress', 'completed', 'cancelled'].includes(status)) {
        return res.status(400).json({
          error: 'Invalid status',
          code: 'INVALID_STATUS'
        });
      }

      if (priority && !['low', 'medium', 'high'].includes(priority)) {
        return res.status(400).json({
          error: 'Invalid priority',
          code: 'INVALID_PRIORITY'
        });
      }

      // Handle file upload
      let attachment_path = task.attachment_path;
      let attachment_filename = task.attachment_filename;

      if (req.file) {
        // Delete old file if exists
        if (task.attachment_path) {
          await safeDeleteFile(task.attachment_path);
        }
        attachment_path = req.file.path;
        attachment_filename = req.file.originalname;
      }

      // Update task
      const result = await pool.query(
        `UPDATE tasks
          SET title = COALESCE($1, title),
              description = COALESCE($2, description),
              status = COALESCE($3, status),
              priority = COALESCE($4, priority),
              attachment_path = COALESCE($5, attachment_path),
              attachment_filename = COALESCE($6, attachment_filename),
              due_date = COALESCE($7, due_date)
          WHERE id = $8 AND user_id = $9
          RETURNING *`,
        [
          title?.trim(),
          description?.trim(),
          status,
          priority,
          attachment_path,
          attachment_filename,
          due_date,
          taskId,
          req.user.id
        ]
      );

      res.json({
        success: true,
        task: result.rows[0]
      });
    } catch (error) {
      handleDatabaseError(error, res, 'Failed to update task');
    }
  }
);

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);

    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        error: 'Invalid task ID',
        code: 'INVALID_TASK_ID'
      });
    }

    // Get task to handle attachment cleanup
    const taskResult = await pool.query(
      'SELECT attachment_path FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({
        error: 'Task not found',
        code: 'TASK_NOT_FOUND'
      });
    }

    const task = taskResult.rows[0];

    // Delete attachment if exists
    if (task.attachment_path) {
      await safeDeleteFile(task.attachment_path);
    }

    // Delete task
    await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, req.user.id]
    );

    res.status(204).send();
  } catch (error) {
    handleDatabaseError(error, res, 'Failed to delete task');
  }
});

// Enhanced API health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    const dbStart = Date.now();
    await pool.query('SELECT 1');
    const dbTime = Date.now() - dbStart;

    // Check upload directory
    const uploadDirExists = fsSync.existsSync(CONFIG.UPLOAD_DIR);

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'task-manager-api',
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      database: {
        status: 'connected',
        responseTime: `${dbTime}ms`
      },
      storage: {
        uploadDir: uploadDirExists ? 'available' : 'missing',
        path: CONFIG.UPLOAD_DIR
      },
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'task-manager-api',
      database: {
        status: 'disconnected',
        error: error.message
      },
      uptime: process.uptime()
    });
  }
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', {
    message: error.message,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  if (error instanceof multer.MulterError) {
    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        return res.status(400).json({
          error: 'File size too large. Maximum size is 5MB',
          code: 'FILE_TOO_LARGE'
        });
      case 'LIMIT_FILE_COUNT':
        return res.status(400).json({
          error: 'Too many files. Only one file allowed',
          code: 'TOO_MANY_FILES'
        });
      case 'LIMIT_UNEXPECTED_FILE':
        return res.status(400).json({
          error: 'Unexpected file field',
          code: 'UNEXPECTED_FILE'
        });
      default:
        return res.status(400).json({
          error: 'File upload error',
          code: 'UPLOAD_ERROR'
        });
    }
  }

  res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: `Endpoint ${req.method} ${req.url} not found`,
    code: 'ENDPOINT_NOT_FOUND'
  });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`\n🔄 Received ${signal}, shutting down gracefully...`);

  try {
    await pool.end();
    console.log('✅ Database pool closed');
    console.log('👋 Server shutdown complete');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Initialize and start server with Render-compatible binding
const startServer = async () => {
  console.log('🚀 Starting Task Manager API...');
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️ Upload Directory: ${CONFIG.UPLOAD_DIR}`);

  await initializeDatabase(); // This calls your robust database initialization

  // Render requires binding to 0.0.0.0
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
    console.log(`🏥 Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`🔌 API health: http://0.0.0.0:${PORT}/api/health`);
  });
};

startServer(); // Call the async function to start the server