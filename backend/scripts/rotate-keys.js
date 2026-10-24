// SR-09: Key rotation script.
// Re-encrypts all stored sensitive data with the newest encryption key.
//
// How to rotate keys (every 90 days, or straight away if a key might be leaked):
//   1. Generate a new key:
//        node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
//   2. Add it to .env as DATA_ENCRYPTION_KEY_V2=<new key>
//   3. Set DATA_ENCRYPTION_KEY_VERSION=2 in .env
//   4. Run (from the backend folder):  node scripts/rotate-keys.js
//   5. Once it finishes, the old key can be removed from .env
//
// This uses the ADMIN database user on purpose. The normal app user is
// NOT allowed to update ballots (so votes can't be changed), so only
// this maintenance script, run by an admin, can rewrite them.
// It only changes the encryption, never the actual vote.

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env'), quiet: true });

const { Pool } = require('pg');
const { reencrypt, getCurrentKeyVersion } = require('../src/security/encryption');

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_ADMIN_USER,
  password: process.env.DB_ADMIN_PASSWORD
});

async function rotateKeys() {
  const currentVersion = getCurrentKeyVersion();
  const client = await pool.connect();

  try {
    // Everything happens in one transaction:
    // if anything fails halfway, NOTHING is changed (no half-rotated data)
    await client.query('BEGIN');

    // 1. Users: re-encrypt their personal details and MFA secret
    const users = await client.query(
      `SELECT id, full_name_enc, date_of_birth_enc, address_enc, mfa_secret_enc
       FROM users WHERE key_version < $1 FOR UPDATE`,
      [currentVersion]
    );

    for (const u of users.rows) {
      await client.query(
        `UPDATE users
         SET full_name_enc = $1, date_of_birth_enc = $2, address_enc = $3,
             mfa_secret_enc = $4, key_version = $5
         WHERE id = $6`,
        [
          reencrypt(u.full_name_enc),
          reencrypt(u.date_of_birth_enc),
          reencrypt(u.address_enc),
          reencrypt(u.mfa_secret_enc),
          currentVersion,
          u.id
        ]
      );
    }

    // 2. Ballots: re-encrypt the vote data
    const ballots = await client.query(
      'SELECT id, ballot_data_enc FROM ballots WHERE key_version < $1 FOR UPDATE',
      [currentVersion]
    );

    for (const b of ballots.rows) {
      await client.query(
        'UPDATE ballots SET ballot_data_enc = $1, key_version = $2 WHERE id = $3',
        [reencrypt(b.ballot_data_enc), currentVersion, b.id]
      );
    }

    await client.query('COMMIT');
    console.log(`Done: re-encrypted ${users.rowCount} users and ${ballots.rowCount} ballots with key version ${currentVersion}.`);

  } catch (err) {
    // Something went wrong, so undo everything
    await client.query('ROLLBACK');
    console.error('Key rotation failed, nothing was changed:', err.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

rotateKeys();