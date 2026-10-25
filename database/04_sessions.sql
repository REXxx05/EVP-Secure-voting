-- SR-04: Session isolation and expiry.
-- Stores active login sessions so we can look up, expire, and immediately invalidate them (e.g. on logout or ballot submission).

CREATE TABLE IF NOT EXISTS sessions (
  id              SERIAL PRIMARY KEY,
  token           VARCHAR(255) UNIQUE NOT NULL,
  user_id         INTEGER NOT NULL REFERENCES users(id),
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMP NOT NULL,
  invalidated     BOOLEAN NOT NULL DEFAULT FALSE
);

-- Looking up a session happens on almost every authenticated request, so an index on the token keeps that fast as the table grows.
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);