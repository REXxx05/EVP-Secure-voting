-- SR-17: Privacy-preserving voter security log.
--
-- Stores HMAC-SHA-256 pseudonyms instead of raw voter identifiers.
-- Does not store IP addresses, ballot identifiers, ballot selections,
-- session identifiers, or event timestamps.
--
-- This log is separate from the administrator audit log.

CREATE TABLE IF NOT EXISTS voter_privacy_log (

    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    voter_pseudonym CHAR(64) NOT NULL
        CHECK (voter_pseudonym ~ '^[0-9a-f]{64}$'),

    event_type VARCHAR(50) NOT NULL
        CHECK (
            event_type IN (
                'access.denied',
                'eligibility.denied'
            )
        ),

    reason VARCHAR(50) NOT NULL
        CHECK (
            reason ~ '^[a-z0-9_.-]+$'
        )

);

-- Prevent modification or deletion of existing records.
CREATE OR REPLACE FUNCTION voter_privacy_log_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'voter_privacy_log is append-only'
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER voter_privacy_log_no_update_delete
BEFORE UPDATE OR DELETE ON voter_privacy_log
FOR EACH ROW
EXECUTE FUNCTION voter_privacy_log_append_only();

CREATE TRIGGER voter_privacy_log_no_truncate
BEFORE TRUNCATE ON voter_privacy_log
FOR EACH STATEMENT
EXECUTE FUNCTION voter_privacy_log_append_only();