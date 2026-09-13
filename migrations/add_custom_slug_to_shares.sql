-- Add custom_slug column to shares table
ALTER TABLE shares ADD COLUMN IF NOT EXISTS custom_slug VARCHAR(64) UNIQUE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_custom_slug ON shares(custom_slug);
