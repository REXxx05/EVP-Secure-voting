-- 02_seed.sql
-- Fake test data so everyone in the team has the same starting data.
-- NOTHING here is real: all divisions, parties and candidates are just for testing.
-- Runs automatically after 01_schema.sql when the database is first created.

-- A few electoral divisions to test with
INSERT INTO divisions (name, state) VALUES
  ('Melbourne', 'VIC'),
  ('Kooyong',   'VIC'),
  ('Sydney',    'NSW');

-- One test election that is open for voting
INSERT INTO elections (name, status, opens_at, closes_at) VALUES
  ('2026 Test Federal Election', 'open', now(), now() + interval '30 days');

-- Made-up candidates for each division (election id 1)
-- ballot_order is the order they appear on the ballot paper
INSERT INTO candidates (election_id, division_id, full_name, party, ballot_order) VALUES
  -- Melbourne (division 1)
  (1, 1, 'Alex Turner',  'Harbour Alliance',  1),
  (1, 1, 'Priya Nair',   'Green Valley Party', 2),
  (1, 1, 'Sam Walker',   'Independent',       3),
  -- Kooyong (division 2)
  (1, 2, 'Jordan Lee',   'Harbour Alliance',  1),
  (1, 2, 'Mia Chen',     'Green Valley Party', 2),
  (1, 2, 'Chris Patel',  'Independent',       3),
  -- Sydney (division 3)
  (1, 3, 'Taylor Brooks','Harbour Alliance',  1),
  (1, 3, 'Noah Kim',     'Green Valley Party', 2),
  (1, 3, 'Ella Morris',  'Independent',       3);

-- NOTE: no test users here yet.
-- Users need hashed passwords, and password hashing is part of SR-01,
-- so test users get added once SR-01 is done.