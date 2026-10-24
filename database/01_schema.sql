-- 01_schema.sql
-- Creates the main tables for the EVP.
-- Files in the database folder run automatically (in number order)
-- the first time the Docker database is created.

-- Electoral divisions, e.g. Melbourne, Higgins
CREATE TABLE divisions (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  state VARCHAR(3) NOT NULL
);

-- Each election. Status controls when voting is allowed.
CREATE TABLE elections (
  id SERIAL PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft', 'open', 'closed', 'published')),
  opens_at TIMESTAMPTZ,
  closes_at TIMESTAMPTZ
);

-- Candidates standing in a division for an election
CREATE TABLE candidates (
  id SERIAL PRIMARY KEY,
  election_id INT NOT NULL REFERENCES elections(id),
  division_id INT NOT NULL REFERENCES divisions(id),
  full_name VARCHAR(150) NOT NULL,
  party VARCHAR(100),
  ballot_order INT NOT NULL,
  excluded BOOLEAN NOT NULL DEFAULT FALSE
);

-- Everyone who can log in: voters, admins, auditors and commissioners
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,                -- hashed, never plain text (SR-01)
  role VARCHAR(20) NOT NULL
    CHECK (role IN ('voter', 'admin', 'auditor', 'commissioner')),

  -- Personal details are stored ENCRYPTED (SR-09),
  -- so these columns hold scrambled text, not the real values
  full_name_enc TEXT,
  date_of_birth_enc TEXT,
  address_enc TEXT,
  key_version INT NOT NULL DEFAULT 1,         -- which key encrypted this row (for key rotation)

  -- MFA for admins (SR-02). The secret is encrypted too.
  mfa_secret_enc TEXT,
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,

  -- Used for locking accounts after too many wrong passwords (SR-01)
  failed_logins INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Which voter is enrolled in which division for each election (SR-05)
CREATE TABLE enrolments (
  user_id INT NOT NULL REFERENCES users(id),
  election_id INT NOT NULL REFERENCES elections(id),
  division_id INT NOT NULL REFERENCES divisions(id),
  PRIMARY KEY (user_id, election_id)          -- one enrolment per voter per election
);

-- Records THAT a voter has voted, but not WHAT they voted (SR-06, SR-08).
-- The primary key means the database itself refuses a second vote
-- from the same voter in the same election.
-- No timestamp on purpose, so it can't be matched to when a ballot came in.
CREATE TABLE voter_participation (
  user_id INT NOT NULL REFERENCES users(id),
  election_id INT NOT NULL REFERENCES elections(id),
  PRIMARY KEY (user_id, election_id)
);

-- The actual ballots.
-- There is NO user_id column on purpose (SR-08), so a ballot can't be
-- linked back to the person who cast it.
-- We also use a random UUID instead of 1, 2, 3... so the order ballots
-- were saved in can't be matched against the order voters logged in.
CREATE TABLE ballots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  election_id INT NOT NULL REFERENCES elections(id),
  division_id INT NOT NULL REFERENCES divisions(id),
  ballot_type VARCHAR(10) NOT NULL CHECK (ballot_type IN ('house', 'senate')),
  ballot_data_enc TEXT NOT NULL,              -- the voter's preferences, encrypted (SR-09)
  key_version INT NOT NULL DEFAULT 1
);