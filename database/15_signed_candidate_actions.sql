
-- SR-18: Administrator signing keys and signed candidate actions.

CREATE TABLE admin_signing_keys (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  admin_id INT NOT NULL REFERENCES users(id),
  public_key_pem TEXT NOT NULL,
  key_id VARCHAR(64) NOT NULL UNIQUE,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  CHECK (length(public_key_pem) > 0)
);

CREATE INDEX admin_signing_keys_admin_idx
  ON admin_signing_keys(admin_id);

CREATE TABLE signed_candidate_actions (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  admin_id INT NOT NULL REFERENCES users(id),
  candidate_id INT NOT NULL REFERENCES candidates(id),
  action VARCHAR(30) NOT NULL
    CHECK (action IN ('candidate.order', 'candidate.exclude', 'candidate.restore')),
  new_value VARCHAR(30) NOT NULL,
  signed_at TIMESTAMPTZ NOT NULL,
  signing_key_id BIGINT NOT NULL REFERENCES admin_signing_keys(id),
  signature TEXT NOT NULL,
  CHECK (length(signature) > 0)
);

CREATE INDEX signed_candidate_actions_candidate_idx
  ON signed_candidate_actions(candidate_id);

CREATE INDEX signed_candidate_actions_admin_idx
  ON signed_candidate_actions(admin_id);

-- Prevent modification or removal of signing evidence.
CREATE FUNCTION prevent_signed_candidate_action_changes()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'Signed candidate actions are append-only'
    USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER signed_candidate_actions_no_update_delete
  BEFORE UPDATE OR DELETE ON signed_candidate_actions
  FOR EACH ROW
  EXECUTE FUNCTION prevent_signed_candidate_action_changes();

CREATE TRIGGER signed_candidate_actions_no_truncate
  BEFORE TRUNCATE ON signed_candidate_actions
  FOR EACH STATEMENT
  EXECUTE FUNCTION prevent_signed_candidate_action_changes();

-- Application may read registered public keys and insert signed evidence,
-- but must not modify or delete signing records.
REVOKE ALL ON admin_signing_keys FROM PUBLIC;
REVOKE ALL ON signed_candidate_actions FROM PUBLIC;

GRANT SELECT ON admin_signing_keys TO evp_app;
GRANT INSERT ON signed_candidate_actions TO evp_app;
GRANT USAGE ON SEQUENCE signed_candidate_actions_id_seq TO evp_app;
