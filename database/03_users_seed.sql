
-- SR-01: Fake test accounts for local development and testing.
-- Passwords here are bcrypt hashes of simple test passwords, never
-- real credentials. Everyone on the team can log in locally with these.

-- Plain text password for all three accounts below is: Password123!

INSERT INTO users (username, password_hash, role, failed_login_attempts, locked_until)
VALUES
  ('voter1', '$2b$12$zpbV3oddjROWijguoOuMBOFzFa8Aayyjq7M2TJszDcMZd/YESA71S', 'voter', 0, NULL),
  ('admin1', '$2b$12$zpbV3oddjROWijguoOuMBOFzFa8Aayyjq7M2TJszDcMZd/YESA71S', 'admin', 0, NULL),
  ('auditor1', '$2b$12$zpbV3oddjROWijguoOuMBOFzFa8Aayyjq7M2TJszDcMZd/YESA71S', 'auditor', 0, NULL)
ON CONFLICT (username) DO NOTHING;