// server.js - Main Express Server
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet()); // Security headers
app.use(compression()); // Gzip compression
app.use(morgan('combined')); // Logging
app.use(cors({
  origin: [
    'http://localhost:3000', // Development
    process.env.FRONTEND_URL, // Production CloudFront URL
    'https://d1234567890.cloudfront.net' // Replace with your CloudFront domain
  ],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database connection pool
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'xyz_university',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
};

const pool = mysql.createPool(dbConfig);

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Database connected successfully');
    connection.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    process.exit(1);
  }
}

// Initialize database tables
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    
    // Create students table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS students (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        address TEXT NOT NULL,
        city VARCHAR(100) NOT NULL,
        state VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_name (name),
        INDEX idx_city (city),
        INDEX idx_state (state)
      )
    `);

    // Create audit log table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        action VARCHAR(50) NOT NULL,
        table_name VARCHAR(50) NOT NULL,
        record_id INT,
        old_values JSON,
        new_values JSON,
        user_ip VARCHAR(45),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_action (action),
        INDEX idx_timestamp (timestamp)
      )
    `);

    // Insert sample data if table is empty
    const [rows] = await connection.execute('SELECT COUNT(*) as count FROM students');
    if (rows[0].count === 0) {
      await connection.execute(`
        INSERT INTO students (name, address, city, state, email, phone) VALUES
        ('John Doe', '123 Main Street', 'Springfield', 'Illinois', 'john.doe@example.com', '9009009009'),
        ('Jane Smith', '456 Oak Avenue', 'Madison', 'Wisconsin', 'jane.smith@example.com', '8008008008'),
        ('Michael Johnson', '789 Pine Road', 'Austin', 'Texas', 'michael.johnson@example.com', '7007007007'),
        ('Sarah Williams', '321 Elm Drive', 'Denver', 'Colorado', 'sarah.williams@example.com', '6006006006'),
        ('David Brown', '654 Cedar Lane', 'Seattle', 'Washington', 'david.brown@example.com', '5005005005'),
        ('Emily Davis', '987 Birch Street', 'Portland', 'Oregon', 'emily.davis@example.com', '4004004004'),
        ('Robert Wilson', '246 Maple Avenue', 'Phoenix', 'Arizona', 'robert.wilson@example.com', '3003003003'),
        ('Lisa Anderson', '135 Walnut Drive', 'Miami', 'Florida', 'lisa.anderson@example.com', '2002002002')
      `);
      console.log('✅ Sample data inserted');
    }

    connection.release();
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    process.exit(1);
  }
}

// Audit logging function
async function logAudit(action, tableName, recordId, oldValues, newValues, userIp) {
  try {
    await pool.execute(
      'INSERT INTO audit_logs (action, table_name, record_id, old_values, new_values, user_ip) VALUES (?, ?, ?, ?, ?, ?)',
      [action, tableName, recordId, JSON.stringify(oldValues), JSON.stringify(newValues), userIp]
    );
  } catch (error) {
    console.error('Audit logging failed:', error.message);
  }
}

// Validation middleware
const validateStudent = (req, res, next) => {
  const { name, address, city, state, email, phone } = req.body;
  const errors = [];

  if (!name || name.trim().length < 2) {
    errors.push('Name must be at least 2 characters long');
  }
  if (!address || address.trim().length < 5) {
    errors.push('Address must be at least 5 characters long');
  }
  if (!city || city.trim().length < 2) {
    errors.push('City must be at least 2 characters long');
  }
  if (!state || state.trim().length < 2) {
    errors.push('State must be at least 2 characters long');
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.push('Valid email is required');
  }
  if (!phone || !/^\d{10,15}$/.test(phone.replace(/\D/g, ''))) {
    errors.push('Valid phone number is required (10-15 digits)');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors
    });
  }

  // Sanitize inputs
  req.body.name = name.trim();
  req.body.address = address.trim();
  req.body.city = city.trim();
  req.body.state = state.trim();
  req.body.email = email.trim().toLowerCase();
  req.body.phone = phone.replace(/\D/g, '');

  next();
};

// API Routes

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({
      success: true,
      message: 'Server is healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Database connection failed',
      timestamp: new Date().toISOString()
    });
  }
});

// Get all students with search and pagination
app.get('/api/students', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const search = req.query.search || '';
    const offset = (page - 1) * limit;

    let query = 'SELECT * FROM students';
    let countQuery = 'SELECT COUNT(*) as total FROM students';
    let queryParams = [];

    if (search) {
      const searchCondition = ' WHERE name LIKE ? OR email LIKE ? OR city LIKE ? OR state LIKE ?';
      query += searchCondition;
      countQuery += searchCondition;
      const searchParam = `%${search}%`;
      queryParams = [searchParam, searchParam, searchParam, searchParam];
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);

    const [students] = await pool.execute(query, queryParams);
    const [totalResult] = await pool.execute(countQuery, search ? queryParams.slice(0, 4) : []);
    const total = totalResult[0].total;

    res.json({
      success: true,
      data: students,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching students:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch students',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get single student by ID
app.get('/api/students/:id', async (req, res) => {
  try {
    const { id } = req.params;

    if (!id || isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: 'Valid student ID is required'
      });
    }

    const [students] = await pool.execute('SELECT * FROM students WHERE id = ?', [id]);

    if (students.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }

    res.json({
      success: true,
      data: students[0]
    });
  } catch (error) {
    console.error('Error fetching student:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch student',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Create new student
app.post('/api/students', validateStudent, async (req, res) => {
  try {
    const { name, address, city, state, email, phone } = req.body;
    const userIp = req.ip || req.connection.remoteAddress;

    // Check if email already exists
    const [existingStudents] = await pool.execute('SELECT id FROM students WHERE email = ?', [email]);
    if (existingStudents.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Email already exists'
      });
    }

    const [result] = await pool.execute(
      'INSERT INTO students (name, address, city, state, email, phone) VALUES (?, ?, ?, ?, ?, ?)',
      [name, address, city, state, email, phone]
    );

    const [newStudent] = await pool.execute('SELECT * FROM students WHERE id = ?', [result.insertId]);

    // Log audit
    await logAudit('CREATE', 'students', result.insertId, null, newStudent[0], userIp);

    res.status(201).json({
      success: true,
      message: 'Student created successfully',
      data: newStudent[0]
    });
  } catch (error) {
    console.error('Error creating student:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(409).json({
        success: false,
        message: 'Email already exists'
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to create student',
        error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  }
});

// Update student
app.put('/api/students/:id', validateStudent, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, address, city, state, email, phone } = req.body;
    const userIp = req.ip || req.connection.remoteAddress;

    if (!id || isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: 'Valid student ID is required'
      });
    }

    // Get existing student data
    const [existingStudents] = await pool.execute('SELECT * FROM students WHERE id = ?', [id]);
    if (existingStudents.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }

    // Check if email already exists for other students
    const [emailCheck] = await pool.execute('SELECT id FROM students WHERE email = ? AND id != ?', [email, id]);
    if (emailCheck.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Email already exists'
      });
    }

    const oldData = existingStudents[0];

    await pool.execute(
      'UPDATE students SET name = ?, address = ?, city = ?, state = ?, email = ?, phone = ? WHERE id = ?',
      [name, address, city, state, email, phone, id]
    );

    const [updatedStudent] = await pool.execute('SELECT * FROM students WHERE id = ?', [id]);

    // Log audit
    await logAudit('UPDATE', 'students', id, oldData, updatedStudent[0], userIp);

    res.json({
      success: true,
      message: 'Student updated successfully',
      data: updatedStudent[0]
    });
  } catch (error) {
    console.error('Error updating student:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(409).json({
        success: false,
        message: 'Email already exists'
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to update student',
        error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  }
});

// Delete student
app.delete('/api/students/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const userIp = req.ip || req.connection.remoteAddress;

    if (!id || isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: 'Valid student ID is required'
      });
    }

    // Get existing student data for audit
    const [existingStudents] = await pool.execute('SELECT * FROM students WHERE id = ?', [id]);
    if (existingStudents.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }

    const oldData = existingStudents[0];

    await pool.execute('DELETE FROM students WHERE id = ?', [id]);

    // Log audit
    await logAudit('DELETE', 'students', id, oldData, null, userIp);

    res.json({
      success: true,
      message: 'Student deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting student:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete student',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get statistics
app.get('/api/stats', async (req, res) => {
  try {
    const [totalStudents] = await pool.execute('SELECT COUNT(*) as total FROM students');
    const [totalStates] = await pool.execute('SELECT COUNT(DISTINCT state) as total FROM students');
    const [totalCities] = await pool.execute('SELECT COUNT(DISTINCT city) as total FROM students');
    const [recentStudents] = await pool.execute('SELECT COUNT(*) as total FROM students WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)');
    
    // Top states
    const [topStates] = await pool.execute(`
      SELECT state, COUNT(*) as count 
      FROM students 
      GROUP BY state 
      ORDER BY count DESC 
      LIMIT 5
    `);

    // Top cities
    const [topCities] = await pool.execute(`
      SELECT city, COUNT(*) as count 
      FROM students 
      GROUP BY city 
      ORDER BY count DESC 
      LIMIT 5
    `);

    res.json({
      success: true,
      data: {
        totalStudents: totalStudents[0].total,
        totalStates: totalStates[0].total,
        totalCities: totalCities[0].total,
        recentStudents: recentStudents[0].total,
        topStates,
        topCities
      }
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get audit logs (admin endpoint)
app.get('/api/audit-logs', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const [logs] = await pool.execute(
      'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );

    const [totalResult] = await pool.execute('SELECT COUNT(*) as total FROM audit_logs');
    const total = totalResult[0].total;

    res.json({
      success: true,
      data: logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch audit logs',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received. Shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await testConnection();
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
      console.log(`👥 Students API: http://localhost:${PORT}/api/students`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();