// SR-01: Voter authentication - user lookups and account lockout state.
// This talks to the "users" table that database/01_schema.sql creates.

const pool = require('../config/db');

// Looks up a user by their login username.
// Returns undefined if no such user exists - callers must handle that, not assume a user was found.
async function findByUsername(username) {
  const result = await pool.query(
    'SELECT id, username, password_hash, failed_logins, locked_until, role FROM users WHERE username = $1',
    [username]
  );
  return result.rows[0];
}

// True if this account is currently locked out from a previous string of failed login attempts.
function isLocked(user) {
  if (!user.locked_until) return false;
  return new Date(user.locked_until) > new Date();
}

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Called after a wrong password. Increments the failure counter and,
// once it hits the limit, sets locked_until 15 minutes in the future.
async function recordFailedLogin(userId) {
  const user = await pool.query(
    'SELECT failed_logins FROM users WHERE id = $1',
    [userId]
  );
  const attempts = (user.rows[0]?.failed_logins || 0) + 1;

  if (attempts >= MAX_FAILED_ATTEMPTS) {
    const lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
    await pool.query(
      'UPDATE users SET failed_logins = $1, locked_until = $2 WHERE id = $3',
      [attempts, lockedUntil, userId]
    );
  } else {
    await pool.query(
      'UPDATE users SET failed_logins = $1 WHERE id = $2',
      [attempts, userId]
    );
  }
}

// Called after a correct login. Clears the failure count and any lock,
// so a legitimate login always resets the slate.
async function clearFailedLogins(userId) {
  await pool.query(
    'UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1',
    [userId]
  );
}

module.exports = { findByUsername, isLocked, recordFailedLogin, clearFailedLogins, LOCKOUT_MINUTES };