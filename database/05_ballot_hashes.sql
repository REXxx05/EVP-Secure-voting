-- SR-11: ballot integrity hashes.
-- One SHA-256 based hash per accepted ballot, kept in its own table so that
-- changing a ballot in `ballots` can be detected by comparing it with the hash
-- that was written when the ballot was accepted.
--
-- Append-only: the app user only gets INSERT and SELECT (see roles.sql) and the
-- trigger below also refuses UPDATE, DELETE and TRUNCATE for every role.
--
-- No timestamp and no serial column on purpose (SR-08): the order or time a
-- hash was written must not be usable to match a ballot to a voter.
-- (04 is reserved for 04_audit_log.sql, SR-15.)

CREATE TABLE ballot_hashes (
  ballot_id UUID PRIMARY KEY REFERENCES ballots(id),
  election_id INT NOT NULL REFERENCES elections(id),
  hash CHAR(64) NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE FUNCTION ballot_hashes_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'ballot_hashes is append-only' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER ballot_hashes_no_update_delete
  BEFORE UPDATE OR DELETE ON ballot_hashes
  FOR EACH ROW EXECUTE FUNCTION ballot_hashes_append_only();

CREATE TRIGGER ballot_hashes_no_truncate
  BEFORE TRUNCATE ON ballot_hashes
  FOR EACH STATEMENT EXECUTE FUNCTION ballot_hashes_append_only();
