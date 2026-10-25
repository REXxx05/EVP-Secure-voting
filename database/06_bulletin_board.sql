-- SR-12: public bulletin board of voting receipts.
-- One row per accepted vote. receipt_ref is the SHA-256 of the secret
-- verification code the voter holds, so the table can be shown publicly
-- without anyone being able to guess a voter's code.
--
-- Nothing here identifies a voter or shows a choice (SR-08): no user id, no
-- ballot id, no timestamp. `commitment` is a hash that binds the receipt to the
-- voter's two ballots without revealing them.
--
-- Rows can only be added. The one allowed change is status going from
-- 'accepted' to 'counted' once the election's ballots have passed the SR-11
-- integrity check; a trigger refuses everything else for every role.

CREATE TABLE bulletin_board (
  receipt_ref CHAR(64) PRIMARY KEY CHECK (receipt_ref ~ '^[0-9a-f]{64}$'),
  election_id INT NOT NULL REFERENCES elections(id),
  commitment CHAR(64) NOT NULL CHECK (commitment ~ '^[0-9a-f]{64}$'),
  status VARCHAR(10) NOT NULL DEFAULT 'accepted' CHECK (status IN ('accepted', 'counted'))
);

CREATE INDEX bulletin_board_election_idx ON bulletin_board (election_id);

CREATE FUNCTION bulletin_board_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD.status = 'accepted' AND NEW.status = 'counted'
     AND NEW.receipt_ref = OLD.receipt_ref
     AND NEW.election_id = OLD.election_id
     AND NEW.commitment = OLD.commitment THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'bulletin_board only allows adding rows and accepted -> counted' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER bulletin_board_guard_row
  BEFORE UPDATE OR DELETE ON bulletin_board
  FOR EACH ROW EXECUTE FUNCTION bulletin_board_guard();

CREATE TRIGGER bulletin_board_guard_truncate
  BEFORE TRUNCATE ON bulletin_board
  FOR EACH STATEMENT EXECUTE FUNCTION bulletin_board_guard();
