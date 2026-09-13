-- Migration: Add oauth_provider to users table and make password_hash nullable
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_provider VARCHAR(32);
CREATE INDEX IF NOT EXISTS idx_users_oauth_provider ON users(oauth_provider);
