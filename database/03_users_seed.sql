
-- SR-01: Fake test accounts for local development and testing.
-- Passwords here are bcrypt hashes of simple test passwords, never
-- real credentials. Everyone on the team can log in locally with these.

-- Plain text password for all three accounts below is: Password123!

INSERT INTO users (username, password_hash, role, failed_logins, locked_until)
VALUES
  ('voter1', '$argon2id$v=19$m=65536,p=4,t=3$MOK6AM6WN4TyfbDItoHnxQ$YE7PvlwT6keTpuSX4GlS5GBy2kEr4K0pjLryipkavgQ', 'voter', 0, NULL),
  ('voter2', '$argon2id$v=19$m=65536,p=4,t=3$MOK6AM6WN4TyfbDItoHnxQ$YE7PvlwT6keTpuSX4GlS5GBy2kEr4K0pjLryipkavgQ', 'voter', 0, NULL),
  ('admin1', '$argon2id$v=19$m=65536,p=4,t=3$MOK6AM6WN4TyfbDItoHnxQ$YE7PvlwT6keTpuSX4GlS5GBy2kEr4K0pjLryipkavgQ', 'admin', 0, NULL),
  ('auditor1', '$argon2id$v=19$m=65536,p=4,t=3$MOK6AM6WN4TyfbDItoHnxQ$YE7PvlwT6keTpuSX4GlS5GBy2kEr4K0pjLryipkavgQ', 'auditor', 0, NULL)
ON CONFLICT (username) DO NOTHING;