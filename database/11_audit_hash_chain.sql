-- SR-16: Hash-chained, append-only audit logs.
-- Extends the existing SR-15 audit_log table.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

LOCK TABLE public.audit_log IN ACCESS EXCLUSIVE MODE;

-- Add hash-chain fields.
ALTER TABLE public.audit_log
  ADD COLUMN IF NOT EXISTS previous_hash TEXT,
  ADD COLUMN IF NOT EXISTS entry_hash TEXT;

-- Protected chain head.
CREATE TABLE IF NOT EXISTS public.audit_chain_state (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  last_hash TEXT NOT NULL
);

INSERT INTO public.audit_chain_state (singleton, last_hash)
VALUES (TRUE, repeat('0', 64))
ON CONFLICT (singleton) DO NOTHING;

-- Hash all security-relevant fields.
CREATE OR REPLACE FUNCTION public.calculate_audit_hash(
  p_previous_hash TEXT,
  p_id BIGINT,
  p_actor_id INTEGER,
  p_action TEXT,
  p_target TEXT,
  p_outcome TEXT,
  p_detail TEXT,
  p_occurred_at TIMESTAMPTZ
)
RETURNS TEXT
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT encode(
    public.digest(
      jsonb_build_array(
        p_previous_hash,
        p_id,
        p_actor_id,
        p_action,
        p_target,
        p_outcome,
        p_detail,
        to_char(
          p_occurred_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US'
        )
      )::text,
      'sha256'
    ),
    'hex'
  );
$$;

-- Backfill existing records in their original ID order.
ALTER TABLE public.audit_log
  DISABLE TRIGGER audit_log_no_update_delete;

DO $$
DECLARE
  audit_record RECORD;
  previous_value TEXT := repeat('0', 64);
  calculated_value TEXT;
BEGIN
  FOR audit_record IN
    SELECT *
    FROM public.audit_log
    ORDER BY id
  LOOP
    calculated_value := public.calculate_audit_hash(
      previous_value,
      audit_record.id,
      audit_record.actor_id,
      audit_record.action,
      audit_record.target,
      audit_record.outcome,
      audit_record.detail,
      audit_record.occurred_at
    );

    UPDATE public.audit_log
    SET previous_hash = previous_value,
        entry_hash = calculated_value
    WHERE id = audit_record.id;

    previous_value := calculated_value;
  END LOOP;

  UPDATE public.audit_chain_state
  SET last_hash = previous_value
  WHERE singleton = TRUE;
END;
$$;

ALTER TABLE public.audit_log
  ENABLE TRIGGER audit_log_no_update_delete;

-- Automatically chain every new audit entry.
CREATE OR REPLACE FUNCTION public.audit_log_hash_on_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  previous_value TEXT;
BEGIN
  -- Lock the chain head until the transaction finishes.
  SELECT last_hash INTO STRICT previous_value
  FROM public.audit_chain_state
  WHERE singleton = TRUE
  FOR UPDATE;

  NEW.previous_hash := previous_value;

  NEW.entry_hash := public.calculate_audit_hash(
    NEW.previous_hash,
    NEW.id,
    NEW.actor_id,
    NEW.action,
    NEW.target,
    NEW.outcome,
    NEW.detail,
    NEW.occurred_at
  );

  UPDATE public.audit_chain_state
  SET last_hash = NEW.entry_hash
  WHERE singleton = TRUE;

  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_log_hash_insert
  BEFORE INSERT ON public.audit_log
  FOR EACH ROW
  EXECUTE FUNCTION public.audit_log_hash_on_insert();

ALTER TABLE public.audit_log
  ALTER COLUMN previous_hash SET NOT NULL,
  ALTER COLUMN entry_hash SET NOT NULL;

ALTER TABLE public.audit_log
  ADD CONSTRAINT audit_previous_hash_format
  CHECK (previous_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE public.audit_log
  ADD CONSTRAINT audit_entry_hash_format
  CHECK (entry_hash ~ '^[0-9a-f]{64}$');

-- Maintain application INSERT-only permissions.
REVOKE SELECT, UPDATE, DELETE, TRUNCATE
ON public.audit_log FROM evp_app;

GRANT INSERT ON public.audit_log TO evp_app;

-- Keep chain-state modifications restricted.
REVOKE ALL ON public.audit_chain_state FROM PUBLIC;
REVOKE ALL ON public.audit_chain_state FROM evp_app;

-- Prevent direct execution of internal functions.
REVOKE ALL ON FUNCTION public.audit_log_hash_on_insert()
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.calculate_audit_hash(
  TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ
) FROM PUBLIC;

COMMIT;