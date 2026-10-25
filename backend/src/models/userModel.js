// SR-01: Voter authentication - user lookups and account lockout state.

const pool = require('../config/db');

// Looks up a user by their login identifier (e.g. email).
// Returns undefined if no such user exists - callers must handle that,
async function findUserByEmail(email) {
  const result = await pool.query(
    'SELECT id, email, password_hash, failed_login_attempts, locked_until, role FROM users WHERE email = $1',
    [email]
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

// Called after a wrong password. Increments the failure counter and,once it hits the limit, sets locked_until 15 minutes in the future.
async function recordFailedLogin(userId) {
  const user = await pool.query(
    'SELECT failed_login_attempts FROM users WHERE id = $1',
    [userId]
  );
  const attempts = (user.rows[0]?.failed_login_attempts || 0) + 1;

  if (attempts >= MAX_FAILED_ATTEMPTS) {
    const lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
    await pool.query(
      'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
      [attempts, lockedUntil, userId]
    );
  } else {
    await pool.query(
      'UPDATE users SET failed_login_attempts = $1 WHERE id = $2',
      [attempts, userId]
    );
  }
}

// Called after a correct login. Clears the failure count and any lock
async function clearFailedLogins(userId) {
  await pool.query(
    'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1',
    [userId]
  );
}

module.exports = { findUserByEmail, isLocked, recordFailedLogin, clearFailedLogins };