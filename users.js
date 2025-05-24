const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const db = require('../config/database');

const router = express.Router();

// Update user profile
router.put('/profile', [
    body('firstName').optional().trim().isLength({ min: 1 }),
    body('lastName').optional().trim().isLength({ min: 1 }),
    body('email').optional().isEmail().normalizeEmail()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const { firstName, lastName, email } = req.body;
        const updates = [];
        const values = [];
        let valueIndex = 1;

        if (firstName) {
            updates.push(`first_name = $${valueIndex++}`);
            values.push(firstName);
        }
        if (lastName) {
            updates.push(`last_name = $${valueIndex++}`);
            values.push(lastName);
        }
        if (email) {
            // Check if email already exists for another user
            const existingUser = await db.query(
                'SELECT id FROM users WHERE email = $1 AND id != $2',
                [email, req.user.id]
            );
            if (existingUser.rows.length > 0) {
                return res.status(409).json({ error: 'Email already in use' });
            }
            updates.push(`email = $${valueIndex++}`);
            values.push(email);
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        updates.push(`updated_at = NOW()`);
        values.push(req.user.id);

        const result = await db.query(`
            UPDATE users 
            SET ${updates.join(', ')}
            WHERE id = $${valueIndex}
            RETURNING id, email, first_name, last_name, plan_type
        `, values);

        res.json({
            success: true,
            user: result.rows[0]
        });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Change password
router.put('/password', [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const { currentPassword, newPassword } = req.body;

        // Get current password hash
        const user = await db.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.id]
        );

        // Verify current password
        const validPassword = await bcrypt.compare(currentPassword, user.rows[0].password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const newPasswordHash = await bcrypt.hash(newPassword, 12);

        // Update password
        await db.query(`
            UPDATE users 
            SET password_hash = $1, updated_at = NOW()
            WHERE id = $2
        `, [newPasswordHash, req.user.id]);

        // Invalidate all other sessions (force re-login)
        await db.query(`
            UPDATE user_sessions 
            SET is_active = false 
            WHERE user_id = $1 AND token_jti != $2
        `, [req.user.id, req.sessionJti]);

        res.json({ success: true, message: 'Password updated successfully' });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Get user dashboard stats
router.get('/dashboard', async (req, res) => {
    try {
        const currentMonth = new Date().toISOString().slice(0, 7);
        
        // Get usage stats
        const usage = await db.query(`
            SELECT views_count, uploads_count 
            FROM usage_stats 
            WHERE user_id = $1 AND month_year = $2
        `, [req.user.id, currentMonth]);

        // Get domains
        const domains = await db.query(`
            SELECT domain_name, status, created_at 
            FROM domains 
            WHERE user_id = $1 AND status = 'active'
            ORDER BY created_at ASC
        `, [req.user.id]);

        // Calculate trial days remaining
        const trialEndsAt = new Date(req.user.trial_ends_at);
        const now = new Date();
        const trialDaysRemaining = Math.max(0, Math.ceil((trialEndsAt - now) / (1000 * 60 * 60 * 24)));

        const userStats = usage.rows[0] || { views_count: 0, uploads_count: 0 };

        res.json({
            stats: {
                uploadsUsed: userStats.uploads_count,
                uploadsLimit: req.user.max_uploads,
                viewsUsed: userStats.views_count,
                viewsLimit: req.user.max_views,
                domainsUsed: domains.rows.length,
                domainsLimit: req.user.max_domains,
                trialDaysRemaining
            },
            domains: domains.rows,
            plan: {
                type: req.user.plan_type,
                status: req.user.plan_status
            }
        });

    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to get dashboard data' });
    }
});

module.exports = router;
