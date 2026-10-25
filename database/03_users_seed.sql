
-- SR-01: Fake test accounts for local development and testing.
-- Passwords here are bcrypt hashes of simple test passwords, never
-- real credentials. Everyone on the team can log in locally with these.

-- Plain text password for all three accounts below is: Password123!

INSERT INTO users (username, password_hash, role, failed_login_attempts, locked_until)
VALUES
  ('voter1', '$argon2id$v=19$m=65536,p=4,t=3$9VhwIzbkndpLSBFlrRV81w$aRIj4L4vV3XbPFvDAjpR3VkNMZMaZDx59nvCU30ETs', 'voter', 0, NULL),
  ('admin1', '$argon2id$v=19$m=65536,p=4,t=3$9VhwIzbkndpLSBFlrRV81w$aRIj4L4vV3XbPFvDAjpR3VkNMZMaZDx59nvCU30ETs', 'admin', 0, NULL),
  ('auditor1', '$argon2id$v=19$m=65536,p=4,t=3$9VhwIzbkndpLSBFlrRV81w$aRIj4L4vV3XbPFvDAjpR3VkNMZMaZDx59nvCU30ETs', 'auditor', 0, NULL)
ON CONFLICT (username) DO NOTHING;