const db = require('../config/database');

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
                month_year VARCHAR(7) NOT NULL, -- Format: "2025-01"
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(user_id, month_year)
            );
        `);

        // User sessions table (for logout functionality)
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

        // Create indexes for better performance
        await db.query(`
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
            CREATE INDEX IF NOT EXISTS idx_domains_domain_name ON domains(domain_name);
            CREATE INDEX IF NOT EXISTS idx_usage_stats_user_month ON usage_stats(user_id, month_year);
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_jti);
        `);

        console.log('✅ Database tables created successfully!');
        
        // Create a test user for development
        if (process.env.NODE_ENV === 'development') {
            const bcrypt = require('bcrypt');
            const testPassword = await bcrypt.hash('demo123', 10);
            
            await db.query(`
                INSERT INTO users (email, password_hash, first_name, last_name, plan_type)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (email) DO NOTHING
            `, ['demo@vaultembed.com', testPassword, 'Demo', 'User', 'creator']);
            
            console.log('✅ Test user created: demo@vaultembed.com / demo123');
        }
        
    } catch (error) {
        console.error('❌ Error creating tables:', error);
        throw error;
    }
}

// Run if called directly
if (require.main === module) {
    createTables()
        .then(() => {
            console.log('🎉 Database setup complete!');
            process.exit(0);
        })
        .catch((error) => {
            console.error('💥 Database setup failed:', error);
            process.exit(1);
        });
}

module.exports = { createTables };