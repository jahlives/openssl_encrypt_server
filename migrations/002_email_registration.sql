-- Migration 002: Email-confirmed keyserver registration
-- Adds pending registration table and email column to ks_clients

-- Pending registrations (30-min TTL, cleaned up periodically)
CREATE TABLE IF NOT EXISTS ks_pending_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    confirmation_token VARCHAR(64) NOT NULL UNIQUE,
    registration_id VARCHAR(64) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    client_id VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_ks_pending_registrations_email
    ON ks_pending_registrations (email);
CREATE INDEX IF NOT EXISTS ix_ks_pending_registrations_confirmation_token
    ON ks_pending_registrations (confirmation_token);
CREATE INDEX IF NOT EXISTS ix_ks_pending_registrations_registration_id
    ON ks_pending_registrations (registration_id);

-- Add email column to existing clients table
ALTER TABLE ks_clients
    ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;

CREATE INDEX IF NOT EXISTS ix_ks_clients_email
    ON ks_clients (email);
