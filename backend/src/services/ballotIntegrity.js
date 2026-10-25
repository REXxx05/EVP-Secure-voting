// SR-11: ballot integrity.
//
// When a ballot is accepted we store a SHA-256 based hash of it in a separate
// append-only table (ballot_hashes). Before anything tallies ballots we
// recompute every hash and compare, so a changed, removed or injected ballot
// is caught before it can reach a count.
//
// The hash is HMAC-SHA-256 keyed with BALLOT_INTEGRITY_KEY (kept in .env, not
// the database). A plain SHA-256 of the ballot would let anyone who can read
// the hash table guess the (small) set of possible ballots and learn how
// people voted without ever touching the encryption key (SR-09). Hashing the
// plaintext also means key rotation (which re-encrypts ballots) does not
// change the hash.

const crypto = require('crypto');
const path = require('path');
const { decrypt } = require('../security/encryption');

require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

const HASH_VERSION = 'evp-ballot-integrity-v1';

class IntegrityError extends Error {
  constructor(message, mismatches) {
    super(message);
    this.name = 'IntegrityError';
    this.code = 'INTEGRITY_FAILURE';
    this.mismatches = mismatches;
  }
}

function getIntegrityKey() {
  const keyBase64 = process.env.BALLOT_INTEGRITY_KEY;
  if (!keyBase64) {
    throw new Error('BALLOT_INTEGRITY_KEY is missing');
  }
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length < 32) {
    throw new Error('BALLOT_INTEGRITY_KEY must be at least 32 bytes');
  }
  return key;
}

// The hash covers the ballot's identity and where it belongs, not only its
// content, so moving a ballot to another election/division/chamber is detected.
function computeBallotHash({ id, electionId, divisionId, ballotType, plaintext }) {
  const canonical = [HASH_VERSION, id, electionId, divisionId, ballotType, plaintext].join('\n');
  return crypto.createHmac('sha256', getIntegrityKey()).update(canonical, 'utf8').digest('hex');
}

// Called inside SR-06's transaction, after the ballot row has been written.
// Reads the stored row back so the hash is of what was actually saved.
async function recordBallotHash(client, ballotId) {
  const result = await client.query(
    'SELECT id, election_id, division_id, ballot_type, ballot_data_enc FROM ballots WHERE id = $1',
    [ballotId]
  );
  if (result.rowCount !== 1) {
    throw new Error('Cannot record integrity hash: ballot not found');
  }
  const row = result.rows[0];
  const hash = computeBallotHash({
    id: row.id,
    electionId: row.election_id,
    divisionId: row.division_id,
    ballotType: row.ballot_type,
    plaintext: decrypt(row.ballot_data_enc)
  });
  await client.query(
    'INSERT INTO ballot_hashes (ballot_id, election_id, hash) VALUES ($1, $2, $3)',
    [row.id, row.election_id, hash]
  );
  return hash;
}

function safeEqualHex(a, b) {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// Recomputes the hash of every ballot in an election and compares it with the
// stored one. Returns the decrypted ballots too, from the same snapshot, so a
// tally can use exactly what was verified.
async function verifyElection(runner, electionId) {
  if (!Number.isSafeInteger(electionId) || electionId < 1) {
    throw new TypeError('A valid election id is required');
  }
  const ballots = await runner.query(
    `SELECT b.id, b.election_id, b.division_id, b.ballot_type, b.ballot_data_enc, h.hash
       FROM ballots b LEFT JOIN ballot_hashes h ON h.ballot_id = b.id
      WHERE b.election_id = $1`,
    [electionId]
  );
  const orphans = await runner.query(
    `SELECT h.ballot_id FROM ballot_hashes h
      WHERE h.election_id = $1 AND NOT EXISTS (SELECT 1 FROM ballots b WHERE b.id = h.ballot_id)`,
    [electionId]
  );

  const mismatches = [];
  const verified = [];
  for (const row of ballots.rows) {
    if (!row.hash) {
      mismatches.push({ ballotId: row.id, reason: 'missing_hash' });
      continue;
    }
    let plaintext;
    try {
      plaintext = decrypt(row.ballot_data_enc);
    } catch (err) {
      mismatches.push({ ballotId: row.id, reason: 'undecryptable' });
      continue;
    }
    const expected = computeBallotHash({
      id: row.id,
      electionId: row.election_id,
      divisionId: row.division_id,
      ballotType: row.ballot_type,
      plaintext
    });
    if (!safeEqualHex(expected, row.hash)) {
      mismatches.push({ ballotId: row.id, reason: 'hash_mismatch' });
      continue;
    }
    verified.push({
      id: row.id,
      divisionId: row.division_id,
      ballotType: row.ballot_type,
      ballotData: JSON.parse(plaintext)
    });
  }
  for (const orphan of orphans.rows) {
    mismatches.push({ ballotId: orphan.ballot_id, reason: 'ballot_missing' });
  }

  return {
    ok: mismatches.length === 0,
    checked: ballots.rowCount + orphans.rowCount,
    mismatches,
    ballots: verified
  };
}

// The gate every tally must go through (SR-13 will call this). One consistent
// snapshot is used, and if anything fails to verify it throws instead of
// returning ballots, so nothing is counted from a tampered set.
async function loadBallotsForTally(pool, electionId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const result = await verifyElection(client, electionId);
    await client.query('COMMIT');
    if (!result.ok) {
      throw new IntegrityError('Ballot integrity check failed; tally blocked', result.mismatches);
    }
    return result.ballots;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (rollbackErr) { /* connection already unusable */ }
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  computeBallotHash,
  recordBallotHash,
  verifyElection,
  loadBallotsForTally,
  IntegrityError
};
