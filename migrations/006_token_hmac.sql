-- Migration 006: Add HMAC columns for constant-time token lookups
-- Replaces direct SQL WHERE equality on confirmation_token and registration_id
-- with indexed HMAC lookup + hmac.compare_digest verification.

-- Add HMAC columns (nullable during migration)
ALTER TABLE ks_pending_registrations
    ADD COLUMN IF NOT EXISTS confirmation_token_hmac VARCHAR(64);

ALTER TABLE ks_pending_registrations
    ADD COLUMN IF NOT EXISTS registration_id_hmac VARCHAR(64);

-- Index for O(1) lookups by HMAC
CREATE INDEX IF NOT EXISTS ix_ks_pending_confirmation_token_hmac
    ON ks_pending_registrations (confirmation_token_hmac);

CREATE INDEX IF NOT EXISTS ix_ks_pending_registration_id_hmac
    ON ks_pending_registrations (registration_id_hmac);

-- Drop old direct indexes (lookups now go through HMAC columns)
DROP INDEX IF EXISTS ix_ks_pending_registrations_confirmation_token;
DROP INDEX IF EXISTS ix_ks_pending_registrations_registration_id;

COMMENT ON COLUMN ks_pending_registrations.confirmation_token_hmac IS 'HMAC-SHA256(server_secret, confirmation_token) for indexed constant-time lookup';
COMMENT ON COLUMN ks_pending_registrations.registration_id_hmac IS 'HMAC-SHA256(server_secret, registration_id) for indexed constant-time lookup';
