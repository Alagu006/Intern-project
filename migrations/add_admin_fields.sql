-- Module 6: Add admin fields to users table
-- Run this migration after existing schema is set up

-- Add role column (default 'user')
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user' NOT NULL;

-- Add is_active column (default true)
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true NOT NULL;

-- Add disabled_at column (nullable)
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

-- Add last_login column (nullable)
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at);

-- Create first admin user (change credentials in production!)
-- Password: Admin1234! (hashed with Argon2)
INSERT INTO users (id, username, email, password_hash, role, is_active, created_at)
VALUES (
    gen_random_uuid(),
    'admin',
    'admin@secure-files.local',
    '$argon2id$v=19$m=65536,t=3,p=4$generated_by_argon2$hash_will_be_here',
    'admin',
    true,
    NOW()
) ON CONFLICT (email) DO NOTHING;

-- Note: You'll need to create the first admin user properly with:
-- python -c "from app.models import User; from app import create_app; from app.extensions import db; app = create_app(); app.app_context().push(); admin = User(username='admin', email='admin@secure-files.local', role='admin'); admin.set_password('Admin1234!'); db.session.add(admin); db.session.commit(); print('Admin created')"
