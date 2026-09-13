-- Migration: Add upload_sessions table for chunked file uploads

CREATE TABLE IF NOT EXISTS upload_sessions (
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

CREATE INDEX IF NOT EXISTS idx_upload_sessions_owner ON upload_sessions(owner_id);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_created_at ON upload_sessions(created_at);
