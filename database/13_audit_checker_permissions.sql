-- ============================================================
-- SR-16: Audit Integrity Checker Database Permissions
-- ============================================================
-- Creates a dedicated PostgreSQL role for checking audit logs.
--
-- Permissions:
-- 1. Read audit records.
-- 2. Read the audit hash-chain state.
-- 3. Calculate and verify audit record hashes.
-- 4. Insert audit integrity alerts.
-- 5. Read the columns returned after inserting an alert.
--
-- The checker cannot modify or delete audit records.
-- ============================================================

BEGIN;

-- Create the dedicated checker role if it does not exist.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'evp_audit_checker'
    ) THEN
        CREATE ROLE evp_audit_checker LOGIN;
    END IF;
END
$$;

-- Allow the checker to connect to the current database.
-- This avoids hard-coding evp_test or evp.
DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO evp_audit_checker',
        current_database()
    );
END
$$;

-- Allow access to the public schema.
GRANT USAGE ON SCHEMA public
TO evp_audit_checker;

-- Allow the checker to read audit records.
GRANT SELECT ON public.audit_log
TO evp_audit_checker;

-- Allow the checker to read the current hash-chain state.
GRANT SELECT ON public.audit_chain_state
TO evp_audit_checker;

-- Allow the checker to create integrity alerts.
GRANT INSERT ON public.audit_integrity_alerts
TO evp_audit_checker;

-- Required because the alert service uses INSERT ... RETURNING.
GRANT SELECT (
    id,
    detected_at,
    issue_count,
    checked_records
)
ON public.audit_integrity_alerts
TO evp_audit_checker;

-- Allow the checker to use the alert ID sequence.
GRANT USAGE ON SEQUENCE public.audit_integrity_alerts_id_seq
TO evp_audit_checker;

-- Allow the checker to recalculate SHA-256 hashes.
GRANT EXECUTE ON FUNCTION public.calculate_audit_hash(
    TEXT,
    BIGINT,
    INTEGER,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TIMESTAMPTZ
)
TO evp_audit_checker;

-- Explicitly deny modification of audit records.
REVOKE UPDATE, DELETE, TRUNCATE
ON public.audit_log
FROM evp_audit_checker;

-- Explicitly deny modification of the hash-chain state.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
ON public.audit_chain_state
FROM evp_audit_checker;

-- Explicitly deny modification of existing integrity alerts.
REVOKE UPDATE, DELETE, TRUNCATE
ON public.audit_integrity_alerts
FROM evp_audit_checker;

COMMIT;