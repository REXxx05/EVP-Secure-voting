-- SR-16: Store audit integrity alerts.
-- Audit records themselves are never modified.

BEGIN;

CREATE TABLE IF NOT EXISTS public.audit_integrity_alerts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    issue_count INTEGER NOT NULL CHECK (issue_count > 0),
    checked_records INTEGER NOT NULL CHECK (checked_records >= 0),
    details JSONB NOT NULL
);

-- Application users must not access integrity alerts.
REVOKE ALL ON public.audit_integrity_alerts FROM PUBLIC;
REVOKE ALL ON public.audit_integrity_alerts FROM evp_app;

-- Prevent ordinary UPDATE and DELETE operations.
CREATE OR REPLACE FUNCTION public.prevent_audit_integrity_alert_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Audit integrity alerts are append-only';
END;
$$;

CREATE TRIGGER audit_integrity_alerts_append_only
BEFORE UPDATE OR DELETE ON public.audit_integrity_alerts
FOR EACH ROW
EXECUTE FUNCTION public.prevent_audit_integrity_alert_changes();

COMMIT;