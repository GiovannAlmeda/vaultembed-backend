const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const db = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Register new user
router.post('/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('firstName').trim().isLength({ min: 1 }),
    body('lastName').trim().isLength({ min: 1 }),
    body('domain').trim().isLength({ min: 1 }),
    body('plan').optional().isIn(['creator', 'pro', 'business'])
], async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const { email, password, firstName, lastName, domain, plan = 'creator' } = req.body;

        // Check if user already exists
        const existingUser = await db.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'User already exists with this email' });
        }

        // Validate domain format
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
        if (!domainRegex.test(domain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }

        // Hash password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Set plan limits
        const planLimits = {
            creator: { maxDomains: 1, maxUploads: 1000, maxViews: 10000 },
            pro: { maxDomains: 2, maxUploads: -1, maxViews: 50000 }, // -1 = unlimited
            business: { maxDomains: 10, maxUploads: -1, maxViews: 250000 }
        };

        const limits = planLimits[plan];

        // Start transaction
        await db.query('BEGIN');

        try {
            // Create user
            const userResult = await db.query(`
                INSERT INTO users (email, password_hash, first_name, last_name, plan_type, max_domains, max_uploads, max_views)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, email, first_name, last_name, plan_type, trial_ends_at
            `, [email, passwordHash, firstName, lastName, plan, limits.maxDomains, limits.maxUploads, limits.maxViews]);

            const user = userResult.rows[0];

            // Add initial domain
            await db.query(`
                INSERT INTO domains (user_id, domain_name)
                VALUES ($1, $2)
            `, [user.id, domain.toLowerCase()]);

            // Create initial usage stats
            const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
            await db.query(`
                INSERT INTO usage_stats (user_id, month_year)
                VALUES ($1, $2)
            `, [user.id, currentMonth]);

            await db.query('COMMIT');

            res.status(201).json({
                success: true,
                message: 'Account created successfully',
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.first_name,
                    lastName: user.last_name,
                    plan: user.plan_type,
                    trialEndsAt: user.trial_ends_at
                }
            });

        } catch (error) {
            await db.query('ROLLBACK');
            throw error;
        }

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to create account' });
    }
});

// Login user
router.post('/login', [
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

        const { email, password, remember = false } = req.body;

        // Get user
        const userResult = await db.query(`
            SELECT id, email, password_hash, first_name, last_name, plan_type, plan_status, 
                   trial_ends_at, max_domains, max_uploads, max_views, is_active
            FROM users 
            WHERE email = $1
        `, [email]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = userResult.rows[0];

        if (!user.is_active) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate session token
        const jti = crypto.randomUUID();
        const expiresIn = remember ? '30d' : '24h';
        const expiresAt = new Date();
        expiresAt.setTime(expiresAt.getTime() + (remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000));

        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email, 
                jti: jti 
            },
            process.env.JWT_SECRET,
            { expiresIn }
        );

        // Store session
        await db.query(`
            INSERT INTO user_sessions (user_id, token_jti, expires_at)
            VALUES ($1, $2, $3)
        `, [user.id, jti, expiresAt]);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                plan: user.plan_type,
                planStatus: user.plan_status,
                trialEndsAt: user.trial_ends_at,
                limits: {
                    maxDomains: user.max_domains,
                    maxUploads: user.max_uploads,
                    maxViews: user.max_views
                }
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout user
router.post('/logout', authenticateToken, async (req, res) => {
    try {
        // Deactivate current session
        await db.query(`
            UPDATE user_sessions 
            SET is_active = false 
            WHERE token_jti = $1
        `, [req.sessionJti]);

        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Logout from all devices
router.post('/logout-all', authenticateToken, async (req, res) => {
    try {
        // Deactivate all sessions for this user
        await db.query(`
            UPDATE user_sessions 
            SET is_active = false 
            WHERE user_id = $1
        `, [req.user.id]);

        res.json({ success: true, message: 'Logged out from all devices' });
    } catch (error) {
        console.error('Logout all error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Get current user info
router.get('/me', authenticateToken, async (req, res) => {
    try {
        // Get user domains
        const domains = await db.query(`
            SELECT domain_name, status, created_at 
            FROM domains 
            WHERE user_id = $1 AND status = 'active'
            ORDER BY created_at ASC
        `, [req.user.id]);

        // Get current month usage
        const currentMonth = new Date().toISOString().slice(0, 7);
        const usage = await db.query(`
            SELECT views_count, uploads_count 
            FROM usage_stats 
            WHERE user_id = $1 AND month_year = $2
        `, [req.user.id, currentMonth]);

        const userStats = usage.rows[0] || { views_count: 0, uploads_count: 0 };

        // Calculate trial days remaining
        const trialEndsAt = new Date(req.user.trial_ends_at);
        const now = new Date();
        const trialDaysRemaining = Math.max(0, Math.ceil((trialEndsAt - now) / (1000 * 60 * 60 * 24)));

        res.json({
            user: {
                id: req.user.id,
                email: req.user.email,
                firstName: req.user.first_name,
                lastName: req.user.last_name,
                plan: req.user.plan_type,
                planStatus: req.user.plan_status,
                trialDaysRemaining,
                limits: {
                    maxDomains: req.user.max_domains,
                    maxUploads: req.user.max_uploads,
                    maxViews: req.user.max_views
                },
                usage: {
                    viewsUsed: userStats.views_count,
                    uploadsUsed: userStats.uploads_count,
                    domainsUsed: domains.rows.length
                },
                domains: domains.rows
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to get user info' });
    }
});

module.exports = router;