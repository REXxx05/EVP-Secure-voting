
// SR-01: Voter authentication.
// Handles hashing and checking passwords so we never store or compare
// plain text passwords anywhere in the app.
//
// We use bcrypt

const bcrypt = require('bcrypt');

// Higher = slower to hash (more secure) but slower to log in.
// 12 is a common default that's still fast enough for a web login.
const SALT_ROUNDS = 12;

// Turns a plain text password into a hash to store in the database.
// Called once, when a user is created or resets their password.
async function hashPassword(plainTextPassword) {
  // Guard clause: fail loudly here rather than letting bcrypt throw
  if (!plainTextPassword || typeof plainTextPassword !== 'string') {
    throw new Error('Password must be a non-empty string');
  }

  // bcrypt.hash() generates the salt internally and returns one string that contains both the salt and the hash, e.g. "$2b$12$...".
  return bcrypt.hash(plainTextPassword, SALT_ROUNDS);
}

// Checks a plain text password (typed at login) against the hash stored
// Returns true/false - never throws just because the password is wrong,
async function verifyPassword(plainTextPassword, storedHash) {
  // If either value is missing, it can't possibly match - skip bcrypt
  if (!plainTextPassword || !storedHash) {
    return false;
  }

  // bcrypt.compare() re-hashes the given password using the salt
  // embedded in storedHash, then checks if the result matches.
  return bcrypt.compare(plainTextPassword, storedHash);
}

module.exports = { hashPassword, verifyPassword };