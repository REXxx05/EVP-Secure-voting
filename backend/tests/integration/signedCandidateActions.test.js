
/**
 * SR-18: Integration tests for digitally signed candidate actions.
 *
 * Tests:
 * 1. Valid signed candidate exclusion
 * 2. Tampered signature rejection
 * 3. Signed candidate-order update
 * 4. Missing signature rejection
 * 5. Wrong administrator identity rejection
 * 6. Wrong administrator signing key rejection
 *
 * Uses the isolated evp_sr17_test PostgreSQL database.
 * Audit logs and signed evidence are not deleted.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');

const {
  signCandidateAction,
  verifyCandidateAction
} = require('../../src/security/adminSigning');

const {
  setCandidateExclusion,
  setCandidateOrder
} = require('../../src/services/adminActions');

jest.setTimeout(15000);

const ADMIN_ID = 3;
const TEST_DB_NAME = 'evp_sr17_test';

const privateKey = fs.readFileSync(
  path.resolve(
    __dirname,
    '../../local-keys/admin1-private.pem'
  ),
  'utf8'
);

const publicKey = fs.readFileSync(
  path.resolve(
    __dirname,
    '../../local-keys/admin1-public.pem'
  ),
  'utf8'
);

let candidateId;
let electionId;
let divisionId;

/**
 * Generate a digitally signed candidate action
 * using the registered administrator's private key.
 */
function makeSignedAction(actionType, newValue) {
  return signCandidateAction(
    {
      adminId: ADMIN_ID,
      candidateId,
      actionType,
      newValue,
      signedAt: new Date().toISOString()
    },
    privateKey
  );
}

/**
 * Read the candidate's current state.
 */
async function getCandidate() {
  const result = await adminDb.query(
    `SELECT id, excluded, ballot_order
     FROM candidates
     WHERE id = $1`,
    [candidateId]
  );

  return result.rows[0];
}

/**
 * Count signed evidence for the test candidate.
 */
async function countSignedActions() {
  const result = await adminDb.query(
    `SELECT COUNT(*)::int AS total
     FROM signed_candidate_actions
     WHERE candidate_id = $1`,
    [candidateId]
  );

  return result.rows[0].total;
}

/**
 * Create isolated election data for SR-18 tests.
 */
beforeAll(async () => {
  if (process.env.DB_NAME !== TEST_DB_NAME) {
    throw new Error(
      `SR-18 integration tests must run against ${TEST_DB_NAME}`
    );
  }

  const election = await adminDb.query(
    `INSERT INTO elections (name, status)
     VALUES ($1, 'draft')
     RETURNING id`,
    [`SR18 test ${crypto.randomUUID()}`]
  );

  electionId = election.rows[0].id;

  const division = await adminDb.query(
    `INSERT INTO divisions (name, state)
     VALUES ($1, 'VIC')
     RETURNING id`,
    [`SR18 division ${crypto.randomUUID()}`]
  );

  divisionId = division.rows[0].id;

  const candidate = await adminDb.query(
    `INSERT INTO candidates
       (election_id, division_id, full_name, ballot_order)
     VALUES ($1, $2, 'SR18 Test Candidate', 1)
     RETURNING id`,
    [electionId, divisionId]
  );

  candidateId = candidate.rows[0].id;
});

/**
 * Close database connections after testing.
 *
 * Do not delete signed evidence or audit records.
 */
afterAll(async () => {
  await db.pool.end();
  await adminDb.end();
});

/**
 * Test 1:
 * A valid administrator signature allows candidate exclusion.
 * The stored signature must verify against the registered public key.
 */
test('a valid signed exclusion is saved and verifies', async () => {
  const signedAction = makeSignedAction(
    'candidate.exclude',
    'true'
  );

  expect(
    verifyCandidateAction(signedAction, publicKey)
  ).toBe(true);

  const outcome = await setCandidateExclusion({
    actorId: ADMIN_ID,
    candidateId,
    excluded: true,
    signedAction
  });

  expect(outcome.audited).toBe(true);

  const candidate = await getCandidate();

  expect(candidate.excluded).toBe(true);

  const evidence = await adminDb.query(
    `SELECT
       sca.admin_id,
       sca.candidate_id,
       sca.action,
       sca.new_value,
       sca.signed_at,
       sca.signature,
       ask.key_id,
       ask.public_key_pem
     FROM signed_candidate_actions sca
     JOIN admin_signing_keys ask
       ON ask.id = sca.signing_key_id
     WHERE sca.candidate_id = $1
     ORDER BY sca.id DESC
     LIMIT 1`,
    [candidateId]
  );

  expect(evidence.rowCount).toBe(1);

  const row = evidence.rows[0];

  expect(row.admin_id).toBe(ADMIN_ID);
  expect(row.candidate_id).toBe(candidateId);
  expect(row.action).toBe('candidate.exclude');
  expect(row.new_value).toBe('true');

  const storedSignedAction = {
    adminId: row.admin_id,
    candidateId: row.candidate_id,
    actionType: row.action,
    newValue: row.new_value,
    signedAt: row.signed_at.toISOString(),
    keyId: row.key_id,
    signature: row.signature
  };

  expect(
    verifyCandidateAction(
      storedSignedAction,
      row.public_key_pem
    )
  ).toBe(true);
});

/**
 * Test 2:
 * A modified signature must be rejected.
 * The candidate must remain excluded.
 */
test(
  'rejects a modified signature without changing the candidate',
  async () => {
    const signedAction = makeSignedAction(
      'candidate.restore',
      'false'
    );

    const invalidAction = {
      ...signedAction,
      signature: 'invalid-signature'
    };

    await expect(
      setCandidateExclusion({
        actorId: ADMIN_ID,
        candidateId,
        excluded: false,
        signedAction: invalidAction
      })
    ).rejects.toThrow(
      'Invalid administrator digital signature'
    );

    const candidate = await getCandidate();

    expect(candidate.excluded).toBe(true);
  }
);

/**
 * Test 3:
 * A valid signed candidate-order change must succeed.
 * The signed evidence must be stored in PostgreSQL.
 */
test(
  'a signed candidate-order change is stored correctly',
  async () => {
    const signedAction = makeSignedAction(
      'candidate.order',
      '2'
    );

    const outcome = await setCandidateOrder({
      actorId: ADMIN_ID,
      candidateId,
      ballotOrder: 2,
      signedAction
    });

    expect(outcome.audited).toBe(true);

    const candidate = await getCandidate();

    expect(candidate.ballot_order).toBe(2);

    const evidence = await adminDb.query(
      `SELECT action, new_value
       FROM signed_candidate_actions
       WHERE candidate_id = $1
       ORDER BY id DESC
       LIMIT 1`,
      [candidateId]
    );

    expect(evidence.rowCount).toBe(1);

    expect(evidence.rows[0]).toMatchObject({
      action: 'candidate.order',
      new_value: '2'
    });
  }
);

/**
 * Test 4:
 * An unsigned candidate-order change must be rejected.
 * The original ballot order must remain unchanged.
 */
test(
  'rejects an unsigned candidate-order change',
  async () => {
    await expect(
      setCandidateOrder({
        actorId: ADMIN_ID,
        candidateId,
        ballotOrder: 5
      })
    ).rejects.toThrow(
      'Missing or mismatched administrator signature'
    );

    const candidate = await getCandidate();

    expect(candidate.ballot_order).toBe(2);
  }
);

/**
 * Test 5:
 * Changing the administrator identity in a signed
 * request must not authorise another administrator.
 */
test(
  'rejects a signature attributed to another administrator',
  async () => {
    const signedAction = makeSignedAction(
      'candidate.order',
      '6'
    );

    const forgedAction = {
      ...signedAction,
      adminId: ADMIN_ID + 1
    };

    await expect(
      setCandidateOrder({
        actorId: ADMIN_ID,
        candidateId,
        ballotOrder: 6,
        signedAction: forgedAction
      })
    ).rejects.toThrow(
      'Missing or mismatched administrator signature'
    );

    const candidate = await getCandidate();

    expect(candidate.ballot_order).toBe(2);
  }
);

/**
 * Test 6:
 * A different private key must not authorise an action
 * for admin1, even when the signed payload claims
 * the correct administrator identity.
 *
 * This key pair exists only in memory.
 */
test(
  'rejects a candidate change signed with an unregistered administrator key',
  async () => {
    const wrongKeyPair = crypto.generateKeyPairSync(
      'ed25519'
    );

    const wrongPrivateKey = wrongKeyPair.privateKey;
    const wrongPublicKey = wrongKeyPair.publicKey;

    const forgedAction = signCandidateAction(
      {
        adminId: ADMIN_ID,
        candidateId,
        actionType: 'candidate.order',
        newValue: '7',
        signedAt: new Date().toISOString()
      },
      wrongPrivateKey
    );

    // The signature is cryptographically valid
    // for the wrong public key.
    expect(
      verifyCandidateAction(
        forgedAction,
        wrongPublicKey
      )
    ).toBe(true);

    // It must not verify against admin1's
    // registered public key.
    expect(
      verifyCandidateAction(
        forgedAction,
        publicKey
      )
    ).toBe(false);

    const beforeEvidence = await countSignedActions();

    // The database service must reject the key because
    // it is not registered to the acting administrator.
    await expect(
      setCandidateOrder({
        actorId: ADMIN_ID,
        candidateId,
        ballotOrder: 7,
        signedAction: forgedAction
      })
    ).rejects.toThrow(
      'Administrator signing key is not registered'
    );

    // The candidate must remain unchanged.
    const candidate = await getCandidate();

    expect(candidate.ballot_order).toBe(2);

    // No signed-action evidence may be inserted
    // for the rejected operation.
    const afterEvidence = await countSignedActions();

    expect(afterEvidence).toBe(beforeEvidence);
  }
);
