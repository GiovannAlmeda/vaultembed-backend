const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || process.env.POSTGRES_DB,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const db = {
    query: (text, params) => pool.query(text, params),
    pool
};

// Test connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Database connection error:', err.stack);
        return;
    }
    console.log('✅ Database connected successfully');
    release();
});

// Database setup function
async function createTables() {
    try {
        console.log('🔧 Creating database tables...');

        // Users table
        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL,
                plan_type VARCHAR(50) DEFAULT 'creator',
                plan_status VARCHAR(50) DEFAULT 'trial',
                trial_ends_at TIMESTAMP DEFAULT (NOW() + INTERVAL '30 days'),
                max_domains INTEGER DEFAULT 1,
                max_uploads INTEGER DEFAULT 1000,
                max_views INTEGER DEFAULT 10000,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                stripe_customer_id VARCHAR(255),
                is_active BOOLEAN DEFAULT true
            );
        `);

        // Domains table
        await db.query(`
            CREATE TABLE IF NOT EXISTS domains (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                domain_name VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(user_id, domain_name)
            );
        `);

        // Usage stats table
        await db.query(`
            CREATE TABLE IF NOT EXISTS usage_stats (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                views_count INTEGER DEFAULT 0,
                uploads_count INTEGER DEFAULT 0,
                month_year VARCHAR(7) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(user_id, month_year)
            );
        `);

        // User sessions table
        await db.query(`
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_jti VARCHAR(255) NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                is_active BOOLEAN DEFAULT true
            );
        `);

        console.log('✅ Database tables created successfully!');
        
    } catch (error) {
        console.error('❌ Error creating tables:', error);
        throw error;
    }
}

// Middleware
app.use(helmet());
app.use(cors({
    origin: true,
    credentials: true
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'VaultEmbed API is working!',
        timestamp: new Date().toISOString()
    });
});

// Register endpoint
app.post('/api/auth/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('firstName').trim().isLength({ min: 1 }),
    body('lastName').trim().isLength({ min: 1 }),
    body('domain').trim().isLength({ min: 1 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const { email, password, firstName, lastName, domain } = req.body;

        // Check if user exists
        const existingUser = await db.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'User already exists' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);

        // Create user
        const userResult = await db.query(`
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, first_name, last_name, plan_type
        `, [email, passwordHash, firstName, lastName]);

        const user = userResult.rows[0];

        // Add domain
        await db.query(`
            INSERT INTO domains (user_id, domain_name)
            VALUES ($1, $2)
        `, [user.id, domain.toLowerCase()]);

        res.status(201).json({
            success: true,
            message: 'Account created successfully',
            user: user
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to create account' });
    }
});

// Login endpoint
app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const { email, password } = req.body;

        // Get user
        const userResult = await db.query(`
            SELECT id, email, password_hash, first_name, last_name, plan_type
            FROM users 
            WHERE email = $1 AND is_active = true
        `, [email]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = userResult.rows[0];

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate token
        const jti = crypto.randomUUID();
        const token = jwt.sign(
            { userId: user.id, email: user.email, jti: jti },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                plan: user.plan_type
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal server error'
    });
});

app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Route not found'
    });
});

// Start server
async function startServer() {
    try {
        console.log('🔧 Setting up database...');
        await createTables();
        console.log('✅ Database setup complete!');
        
        app.listen(PORT, () => {
            console.log(`🚀 VaultEmbed API running on port ${PORT}`);
            console.log(`🔗 Health check: http://localhost:${PORT}/health`);
            console.log(`🧪 Test endpoint: http://localhost:${PORT}/api/test`);
        });
    } catch (error) {
        console.error('💥 Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
