-- SR-01: Fake test accounts for local development and testing.
-- Passwords here are bcrypt hashes of simple test passwords - never real credentials.
-- Plain text password for all three accounts below is: Password123!
INSERT INTO users (email, password_hash, role, failed_login_attempts, locked_until)
VALUES
  ('voter1@test.evp', '$2b$12$zpbV3oddjROWijguoOuMBOFzFa8Aayyjq7M2TJszDcMZd/YESA71S', 'voter', 0, NULL),
  ('admin1@test.evp', '$2b$12$zpbV3oddjROWijguoOuMBOFzFa8Aayyjq7M2TJszDcMZd/YESA71S', 'admin', 0, NULL),
  ('auditor1@test.evp', '$2b$12$zpbV3oddjROWijguoOuMBOFzFa8Aayyjq7M2TJszDcMZd/YESA71S', 'auditor', 0, NULL)
ON CONFLICT (email) DO NOTHING;