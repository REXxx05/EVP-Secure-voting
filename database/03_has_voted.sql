-- SR-08: voter anonymity.
-- The app isn't allowed to read the voter_participation table directly,
-- because if someone could read both that table and the ballots table
-- they might be able to match voters to their ballots.
-- So instead the app uses this small function, which only answers
-- "has this person voted in this election?" with yes or no.

CREATE FUNCTION has_voted(p_user_id INT, p_election_id INT)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public   -- stops anyone tricking it into using a fake table
AS $$
  SELECT EXISTS (
    SELECT 1 FROM voter_participation
    WHERE user_id = p_user_id AND election_id = p_election_id
  );
$$;