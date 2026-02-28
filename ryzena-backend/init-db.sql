-- R.Y.Z.E.N.A. Database Initialization
-- Run this before starting the application

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create indexes for common queries (Prisma will handle the rest)
-- These are additional optimizations for production

-- Create read-only user for analytics
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ryzena_readonly') THEN
        CREATE ROLE ryzena_readonly WITH LOGIN PASSWORD 'readonly_password';
    END IF;
END
$$;

-- Grant read-only access to analytics user
GRANT CONNECT ON DATABASE ryzena TO ryzena_readonly;
GRANT USAGE ON SCHEMA public TO ryzena_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ryzena_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ryzena_readonly;

-- Create audit log table (if not created by Prisma)
CREATE TABLE IF NOT EXISTS security_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action VARCHAR(100) NOT NULL,
    actor_id VARCHAR(100) NOT NULL,
    actor_role VARCHAR(50) NOT NULL,
    resource VARCHAR(255),
    resource_id VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for audit log queries
CREATE INDEX IF NOT EXISTS idx_audit_actor ON security_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON security_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON security_audit_log(created_at);

-- Create partition function for audit logs (for large deployments)
-- This would be enabled for production with high volume

-- Set statement timeout for safety
ALTER DATABASE ryzena SET statement_timeout = '30s';

-- Set default transaction isolation
ALTER DATABASE ryzena SET default_transaction_isolation = 'read committed';
