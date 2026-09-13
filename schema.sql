-- PostgreSQL schema for Secure File Sharing System
-- This is a reference; actual migrations are managed by Flask-Migrate / Alembic

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    oauth_provider VARCHAR(32),
    totp_secret VARCHAR(64),
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    disabled_at TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    storage_quota_bytes BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_oauth_provider ON users(oauth_provider);

-- Folders table
CREATE TABLE folders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_folders_owner ON folders(owner_id);
CREATE INDEX idx_folders_parent ON folders(parent_id);

-- Tags table
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tag_owner_name UNIQUE (owner_id, name)
);

CREATE INDEX idx_tags_owner ON tags(owner_id);
CREATE INDEX idx_tags_name ON tags(name);

-- Files table
CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id UUID REFERENCES folders(id) ON DELETE SET NULL,
    filename VARCHAR(512) NOT NULL,
    mime_type VARCHAR(128) NOT NULL DEFAULT 'application/octet-stream',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    encrypted_path TEXT NOT NULL,
    nonce_hex VARCHAR(24) NOT NULL,
    wrapped_key_hex TEXT NOT NULL,
    auto_delete_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_owner ON files(owner_id);
CREATE INDEX idx_files_folder ON files(folder_id);
CREATE INDEX idx_files_auto_delete ON files(auto_delete_at);
CREATE INDEX idx_files_deleted_at ON files(deleted_at);

-- File-Tags association table
CREATE TABLE file_tags (
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (file_id, tag_id)
);

CREATE INDEX idx_file_tags_file ON file_tags(file_id);
CREATE INDEX idx_file_tags_tag ON file_tags(tag_id);

-- File versions table
CREATE TABLE file_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    filename VARCHAR(512) NOT NULL,
    mime_type VARCHAR(128) NOT NULL DEFAULT 'application/octet-stream',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    encrypted_path TEXT NOT NULL,
    nonce_hex VARCHAR(24) NOT NULL,
    wrapped_key_hex TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_file_version_number UNIQUE (file_id, version_number)
);

CREATE INDEX idx_file_versions_file ON file_versions(file_id);

-- Shares table
CREATE TABLE shares (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,  -- NULL = open link
    can_view BOOLEAN NOT NULL DEFAULT true,
    can_download BOOLEAN NOT NULL DEFAULT false,
    can_edit BOOLEAN NOT NULL DEFAULT false,
    can_reshare BOOLEAN NOT NULL DEFAULT false,
    share_token VARCHAR(64) UNIQUE NOT NULL,
    custom_slug VARCHAR(64) UNIQUE,
    password_hash TEXT,
    expires_at TIMESTAMPTZ,
    pinned_version INTEGER,  -- NULL = dynamic (always tracks latest version)
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shares_file ON shares(file_id);
CREATE INDEX idx_shares_owner ON shares(owner_id);
CREATE INDEX idx_shares_recipient ON shares(recipient_id);
CREATE UNIQUE INDEX idx_shares_token ON shares(share_token);
CREATE UNIQUE INDEX idx_shares_custom_slug ON shares(custom_slug);

-- Access logs table
CREATE TABLE access_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    share_id UUID NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    accessed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address VARCHAR(45),
    action VARCHAR(32) NOT NULL,
    success BOOLEAN NOT NULL,
    detail TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_logs_share ON access_logs(share_id);
CREATE INDEX idx_access_logs_timestamp ON access_logs(timestamp);

-- Notifications table
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    message TEXT NOT NULL,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    related_share_id UUID REFERENCES shares(id) ON DELETE SET NULL
);

CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_created_at ON notifications(created_at);
CREATE INDEX idx_notifications_read_at ON notifications(read_at);
CREATE INDEX idx_notifications_share ON notifications(related_share_id);

-- Personal Access Tokens table
CREATE TABLE personal_access_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_pat_user ON personal_access_tokens(user_id);
CREATE INDEX idx_pat_hash ON personal_access_tokens(token_hash);

-- Upload Sessions table (Chunked uploads)
CREATE TABLE upload_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(512) NOT NULL DEFAULT 'upload',
    mime_type VARCHAR(128) NOT NULL DEFAULT 'application/octet-stream',
    total_size_bytes BIGINT,
    expected_chunks INTEGER NOT NULL,
    received_chunks INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'in_progress',
    folder_id UUID REFERENCES folders(id) ON DELETE SET NULL,
    auto_delete_at TIMESTAMPTZ,
    tags TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_upload_sessions_owner ON upload_sessions(owner_id);
CREATE INDEX idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX idx_upload_sessions_created_at ON upload_sessions(created_at);

-- Webhooks table (Outbound event notifications)
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url VARCHAR(2048) NOT NULL,
    secret VARCHAR(128) NOT NULL,
    event_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_user ON webhooks(user_id);
CREATE INDEX idx_webhooks_active ON webhooks(is_active);

-- WebAuthn Credentials table (Passkeys)
CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    nickname VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credentials_cred_id ON webauthn_credentials(credential_id);

-- Sample queries

-- Find all active shares for a file
SELECT s.*, u.username AS recipient_username
FROM shares s
LEFT JOIN users u ON s.recipient_id = u.id
WHERE s.file_id = '<file-uuid>'
  AND s.is_revoked = false
  AND (s.expires_at IS NULL OR s.expires_at > NOW());

-- Audit trail for a share
SELECT al.*, u.username AS accessed_by_username
FROM access_logs al
LEFT JOIN users u ON al.accessed_by = u.id
WHERE al.share_id = '<share-uuid>'
ORDER BY al.timestamp DESC;

-- Files shared with a user
SELECT f.*, s.permissions, s.share_token
FROM files f
JOIN shares s ON f.id = s.file_id
WHERE s.recipient_id = '<user-uuid>'
  AND s.is_revoked = false
  AND (s.expires_at IS NULL OR s.expires_at > NOW());

-- Most accessed files (top 10)
SELECT f.filename, COUNT(al.id) AS access_count
FROM files f
JOIN shares s ON f.id = s.file_id
JOIN access_logs al ON s.id = al.share_id
WHERE al.success = true
GROUP BY f.id, f.filename
ORDER BY access_count DESC
LIMIT 10;
