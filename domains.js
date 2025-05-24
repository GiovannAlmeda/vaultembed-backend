const express = require('express');
const { body, validationResult } = require('express-validator');
const db = require('../config/database');

const router = express.Router();

// Get user domains
router.get('/', async (req, res) => {
    try {
        const domains = await db.query(`
            SELECT id, domain_name, status, created_at, updated_at
            FROM domains 
            WHERE user_id = $1 
            ORDER BY created_at ASC
        `, [req.user.id]);

        res.json({
            domains: domains.rows,
            usage: {
                used: domains.rows.filter(d => d.status === 'active').length,
                limit: req.user.max_domains
            }
        });
    } catch (error) {
        console.error('Get domains error:', error);
        res.status(500).json({ error: 'Failed to get domains' });
    }
});

// Add new domain
router.post('/', [
    body('domain').trim().notEmpty().isLength({ min: 3, max: 255 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const { domain } = req.body;
        const cleanDomain = domain.toLowerCase().trim();

        // Validate domain format
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
        if (!domainRegex.test(cleanDomain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }

        // Check domain limit
        const currentDomains = await db.query(`
            SELECT COUNT(*) as count 
            FROM domains 
            WHERE user_id = $1 AND status = 'active'
        `, [req.user.id]);

        if (parseInt(currentDomains.rows[0].count) >= req.user.max_domains) {
            return res.status(403).json({ 
                error: 'Domain limit reached',
                currentLimit: req.user.max_domains
            });
        }

        // Check if domain already exists for this user
        const existingDomain = await db.query(`
            SELECT id FROM domains 
            WHERE user_id = $1 AND domain_name = $2
        `, [req.user.id, cleanDomain]);

        if (existingDomain.rows.length > 0) {
            return res.status(409).json({ error: 'Domain already added' });
        }

        // Add domain
        const result = await db.query(`
            INSERT INTO domains (user_id, domain_name)
            VALUES ($1, $2)
            RETURNING id, domain_name, status, created_at
        `, [req.user.id, cleanDomain]);

        res.status(201).json({
            success: true,
            domain: result.rows[0]
        });

    } catch (error) {
        console.error('Add domain error:', error);
        res.status(500).json({ error: 'Failed to add domain' });
    }
});

// Remove domain
router.delete('/:domainId', async (req, res) => {
    try {
        const { domainId } = req.params;

// Remove domain
router.delete('/:domainId', async (req, res) => {
    try {
        const { domainId } = req.params;

        // Verify domain belongs to user
        const domain = await db.query(`
            SELECT id, domain_name FROM domains 
            WHERE id = $1 AND user_id = $2 AND status = 'active'
        `, [domainId, req.user.id]);

        if (domain.rows.length === 0) {
            return res.status(404).json({ error: 'Domain not found' });
        }

        // Soft delete domain
        await db.query(`
            UPDATE domains 
            SET status = 'deleted', updated_at = NOW()
            WHERE id = $1
        `, [domainId]);

        res.json({
            success: true,
            message: 'Domain removed successfully'
        });

    } catch (error) {
        console.error('Remove domain error:', error);
        res.status(500).json({ error: 'Failed to remove domain' });
    }
});

// Get all active domains (for protect.js generation)
router.get('/all-active', async (req, res) => {
    try {
        // This endpoint would be used by your GitHub automation
        // Add authentication check for admin/system access
        
        const domains = await db.query(`
            SELECT DISTINCT domain_name 
            FROM domains 
            WHERE status = 'active'
            ORDER BY domain_name
        `);

        res.json({
            domains: domains.rows.map(d => d.domain_name)
        });

    } catch (error) {
        console.error('Get all domains error:', error);
        res.status(500).json({ error: 'Failed to get domains' });
    }
});

module.exports = router;