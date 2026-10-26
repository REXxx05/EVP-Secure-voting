-- SR-02: adds an "mfa_verified" flag to sessions.
-- Voters don't need MFA. For admins and other staff, the session starts
-- as NOT verified after they enter their password, and only becomes
-- verified once they type a correct 6 digit code from their authenticator app.

ALTER TABLE sessions ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;