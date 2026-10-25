// SR-04: Database access for the sessions table.
// A "session" here is a random, unguessable token issued at login and
// checked on every request after that - the server always decides if it's still valid, not the browser.

const crypto = require('crypto');
const db = require('../config/db');

const SESSION_IDLE_MINUTES = 30;

// Generates a long random token. crypto.randomBytes is cryptographically secure, so an attacker can't guess or predict a valid token.
function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}

// Creates a session row for a freshly logged-in user and returns the token to send back to the client.
async function createSession(userId) {
  const token = generateToken();

  await db.query(
    `INSERT INTO sessions (user_id, token, expires_at)
     VALUES ($1, $2, now() + ($3 || ' minutes')::interval)`,
    [userId, token, SESSION_IDLE_MINUTES]
  );

  return token;
}

// Looks up a session by its token. Returns undefined if there's no
// matching, non-invalidated, non-expired session - callers treat that as "not logged in".
async function findValidSession(token) {
  const result = await db.query(
    `SELECT id, user_id, expires_at
     FROM sessions
     WHERE token = $1
       AND invalidated = FALSE
       AND expires_at > now()`,
    [token]
  );

  return result.rows[0];
}

// Pushes the idle-timeout window out by another 30 minutes, called on
// every authenticated request so an active voter isn't logged out mid-ballot.
async function touchSession(sessionId) {
  await db.query(
    `UPDATE sessions
     SET expires_at = now() + ($2 || ' minutes')::interval
     WHERE id = $1`,
    [sessionId, SESSION_IDLE_MINUTES]
  );
}

// Immediately kills a session (logout, or right after a ballot is submitted - SR-04 requires it can't be reused after that point).
async function invalidateSession(sessionId) {
  await db.query(
    'UPDATE sessions SET invalidated = TRUE WHERE id = $1',
    [sessionId]
  );
}

module.exports = {
  createSession,
  findValidSession,
  touchSession,
  invalidateSession,
  SESSION_IDLE_MINUTES
};