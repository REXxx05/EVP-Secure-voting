// SR-12: anonymous, digitally signed voting receipts and the public bulletin board.
//
// Inside SR-06's transaction (so a vote is only accepted if its receipt was
// recorded too) we:
//   1. make a random verification code (128 bits) that only the voter gets
//   2. put an entry on the bulletin board keyed by SHA-256(code), so the board
//      can be public without exposing codes
//   3. sign { election, code, commitment, key id } with Ed25519
// Nothing here knows who the voter is or what they chose.

const crypto = require('crypto');
const { signReceipt, verifyReceiptSignature, getPublicKey, getKeyId, CODE_PATTERN, HEX64 } =
  require('../security/receiptSigning');
const { loadBallotsForTally } = require('./ballotIntegrity');

const sha256Hex = text => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

// 32 random hex characters shown as 8 groups of 4, e.g. 7F3A-91C0-...
function newVerificationCode() {
  return crypto.randomBytes(16).toString('hex').toUpperCase().match(/.{4}/g).join('-');
}

const receiptRefOf = code => sha256Hex('evp-receipt-ref\n' + code);

// Binds the receipt to the voter's two ballots without revealing them
const commitmentOf = (code, houseBallotId, senateBallotId) =>
  sha256Hex(['evp-receipt-commitment', code, houseBallotId, senateBallotId].join('\n'));

async function issueReceipt(client, { electionId, houseBallotId, senateBallotId }) {
  if (!Number.isSafeInteger(electionId) || electionId < 1 || !houseBallotId || !senateBallotId) {
    throw new Error('Cannot issue receipt: election and both ballot ids are required');
  }
  const verificationCode = newVerificationCode();
  const commitment = commitmentOf(verificationCode, houseBallotId, senateBallotId);
  // Sign first: if signing is not configured the vote fails closed (and rolls back)
  // instead of leaving a board entry that no receipt points to.
  const receipt = signReceipt({ electionId, verificationCode, commitment });
  await client.query(
    'INSERT INTO bulletin_board (receipt_ref, election_id, commitment) VALUES ($1, $2, $3)',
    [receiptRefOf(verificationCode), electionId, commitment]
  );
  return receipt;
}

// What a voter (or anyone holding a receipt) learns from the public board.
//   authentic - the signature verifies against our published key
//   found     - the board has an entry for the code
//   status    - 'accepted' or 'counted'
async function lookupReceipt(runner, receipt) {
  const authentic = verifyReceiptSignature(receipt, getPublicKey());
  if (!authentic) {
    return { authentic: false, found: false };
  }
  const result = await runner.query(
    'SELECT election_id, commitment, status FROM bulletin_board WHERE receipt_ref = $1',
    [receiptRefOf(receipt.verificationCode)]
  );
  if (result.rowCount !== 1) {
    return { authentic: true, found: false };
  }
  const entry = result.rows[0];
  if (entry.election_id !== receipt.electionId || entry.commitment !== receipt.commitment) {
    // Signed receipt that disagrees with the board: report as not matching
    return { authentic: true, found: false };
  }
  return { authentic: true, found: true, status: entry.status };
}

// Public listing of the board for an election, plus a signed head covering it
// so the board's contents can be checked as a whole.
async function getBoard(runner, electionId) {
  if (!Number.isSafeInteger(electionId) || electionId < 1) {
    throw new TypeError('A valid election id is required');
  }
  const result = await runner.query(
    'SELECT receipt_ref, status FROM bulletin_board WHERE election_id = $1 ORDER BY receipt_ref',
    [electionId]
  );
  const entries = result.rows.map(r => ({ receiptRef: r.receipt_ref, status: r.status }));
  const root = sha256Hex(['evp-board', electionId, ...entries.map(e => e.receiptRef)].join('\n'));
  return { electionId, count: entries.length, root, entries };
}

// Moves every receipt of an election to 'counted', but only if the SR-11
// integrity gate passes and the number of receipts equals the number of
// accepted votes (each vote is one House + one Senate ballot).
async function markElectionCounted(pool, electionId) {
  const ballots = await loadBallotsForTally(pool, electionId); // throws on tampering
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const election = await client.query('SELECT status FROM elections WHERE id = $1 FOR SHARE', [electionId]);
    if (election.rowCount !== 1 || election.rows[0].status === 'open' || election.rows[0].status === 'draft') {
      const error = new Error('Receipts can only be marked counted after the election has closed');
      error.code = 'ELECTION_NOT_CLOSED';
      throw error;
    }
    const board = await client.query(
      'SELECT count(*)::int AS n FROM bulletin_board WHERE election_id = $1', [electionId]);
    if (board.rows[0].n * 2 !== ballots.length) {
      const error = new Error('Receipt count does not match accepted ballots; not marking as counted');
      error.code = 'RECEIPT_COUNT_MISMATCH';
      throw error;
    }
    const updated = await client.query(
      "UPDATE bulletin_board SET status = 'counted' WHERE election_id = $1 AND status = 'accepted'",
      [electionId]);
    await client.query('COMMIT');
    return { counted: updated.rowCount };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (rollbackErr) { /* connection unusable */ }
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  issueReceipt, lookupReceipt, getBoard, markElectionCounted,
  newVerificationCode, receiptRefOf, commitmentOf, CODE_PATTERN, HEX64, getKeyId
};
