-- SR-16: Dedicated read-only database role for auditor API.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'evp_audit_reader'
    ) THEN
        CREATE ROLE evp_audit_reader LOGIN;
    END IF;
END
$$;

DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO evp_audit_reader',
        current_database()
    );
END
$$;

GRANT USAGE ON SCHEMA public TO evp_audit_reader;

-- Read audit records and integrity alerts.
GRANT SELECT ON public.audit_log TO evp_audit_reader;
GRANT SELECT ON public.audit_integrity_alerts TO evp_audit_reader;

-- No modification privileges.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
ON public.audit_log
FROM evp_audit_reader;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE
ON public.audit_integrity_alerts
FROM evp_audit_reader;

COMMIT;