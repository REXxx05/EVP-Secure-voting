// SR-01: Voter authentication.
// Handles hashing and checking passwords so we never store or compare
// plain text passwords anywhere in the app.
//
// We use argon2 (specifically argon2id, its default/recommended mode),
// the current best-practice choice for password hashing:
//  - adds a random salt automatically, so two users with the same
//    password get different hashes
//  - deliberately slow and memory-hard, which makes guessing passwords
//    by brute force ,including with GPUs much more expensive

const argon2 = require('argon2');

// Turns a plain text password into a hash to store in the database.
async function hashPassword(plainTextPassword) {
  if (!plainTextPassword || typeof plainTextPassword !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  return argon2.hash(plainTextPassword);
}

// Checks a plain text password against a stored hash.
// Returns true/false, never throws just because the password is wrong
// or the hash is malformed.
async function verifyPassword(plainTextPassword, storedHash) {
  if (!plainTextPassword || !storedHash) {
    return false;
  }
  try {
    return await argon2.verify(storedHash, plainTextPassword);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };