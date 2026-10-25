-- SR-15: audit log of privileged (administrator) actions.
-- One row per successful or failed privileged action. Numbered 04 on purpose
-- (03 is 03_has_voted.sql; 05 and 06 belong to SR-11 and SR-12).
--
-- Rows can only be added: a trigger refuses UPDATE, DELETE and TRUNCATE for every
-- role. (Hash chaining and auditor-only reads are SR-16, not done here.)
-- occurred_at is a TIMESTAMPTZ filled in by the database, so it is an absolute
-- instant that is always read back as UTC.

CREATE TABLE audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_id INT NOT NULL REFERENCES users(id),   -- the administrator
  action VARCHAR(100) NOT NULL,                  -- e.g. candidate.exclude
  target VARCHAR(200) NOT NULL,                  -- e.g. candidate:12
  outcome VARCHAR(10) NOT NULL CHECK (outcome IN ('success', 'failure')),
  detail VARCHAR(100),                           -- short reason code for failures, never user data
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION audit_log_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER audit_log_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
