
/**
 * SR-18: Integration tests for digitally signed candidate actions.
 * Uses the isolated evp_sr17_test PostgreSQL database.
 */

const crypto = require('crypto');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');

const {
  signCandidateAction,
  keyIdOf,
  verifyCandidateAction
} = require('../../src/security/adminSigning');

const {
  setCandidateExclusion,
  setCandidateOrder
} = require('../../src/services/adminActions');

jest.setTimeout(15000);

const TEST_DB_NAME = 'evp_sr17_test';

const testKeyPair = crypto.generateKeyPairSync('ed25519');
const privateKey = testKeyPair.privateKey;
const publicKey = testKeyPair.publicKey;

let adminId;
let candidateId;
let electionId;
let divisionId;

function makeSignedAction(actionType, newValue) {
  return signCandidateAction({
    adminId,
    candidateId,
    actionType,
    newValue,
    signedAt: new Date().toISOString()
  }, privateKey);
}

async function getCandidate() {
  const result = await adminDb.query(
    'SELECT id, excluded, ballot_order FROM candidates WHERE id = $1',
    [candidateId]
  );
  return result.rows[0];
}

async function countSignedActions() {
  const result = await adminDb.query(
    'SELECT COUNT(*)::int AS total FROM signed_candidate_actions WHERE candidate_id = $1',
    [candidateId]
  );
  return result.rows[0].total;
}

beforeAll(async () => {
  if (process.env.DB_NAME !== TEST_DB_NAME) {
    throw new Error(
      `SR-18 integration tests must run against ${TEST_DB_NAME}`
    );
  }

  const admin = await adminDb.query(
    "SELECT id FROM users WHERE username = 'admin1' AND role = 'admin'"
  );

  expect(admin.rowCount).toBe(1);
  adminId = admin.rows[0].id;

  await adminDb.query(
    `INSERT INTO admin_signing_keys
       (admin_id, public_key_pem, key_id)
     VALUES ($1, $2, $3)`,
    [
      adminId,
      publicKey.export({ type: 'spki', format: 'pem' }),
      keyIdOf(publicKey)
    ]
  );

  const election = await adminDb.query(
    `INSERT INTO elections (name, status)
     VALUES ($1, 'draft') RETURNING id`,
    [`SR18 test ${crypto.randomUUID()}`]
  );
  electionId = election.rows[0].id;

  const division = await adminDb.query(
    `INSERT INTO divisions (name, state)
     VALUES ($1, 'VIC') RETURNING id`,
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

afterAll(async () => {
  await db.pool.end();
  await adminDb.end();
});

test('a valid signed exclusion is saved and verifies', async () => {
  const signedAction = makeSignedAction('candidate.exclude', 'true');

  expect(verifyCandidateAction(signedAction, publicKey)).toBe(true);

  const outcome = await setCandidateExclusion({
    actorId: adminId,
    candidateId,
    excluded: true,
    signedAction
  });

  expect(outcome.audited).toBe(true);
  expect((await getCandidate()).excluded).toBe(true);

  const evidence = await adminDb.query(
    `SELECT sca.admin_id, sca.candidate_id, sca.action,
            sca.new_value, sca.signed_at, sca.signature,
            ask.key_id, ask.public_key_pem
     FROM signed_candidate_actions sca
     JOIN admin_signing_keys ask ON ask.id = sca.signing_key_id
     WHERE sca.candidate_id = $1
     ORDER BY sca.id DESC LIMIT 1`,
    [candidateId]
  );

  expect(evidence.rowCount).toBe(1);
  const row = evidence.rows[0];

  expect(row.admin_id).toBe(adminId);
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
    verifyCandidateAction(storedSignedAction, row.public_key_pem)
  ).toBe(true);
});

test('rejects a modified signature without changing the candidate', async () => {
  const signedAction = makeSignedAction('candidate.restore', 'false');
  const invalidAction = {
    ...signedAction,
    signature: 'invalid-signature'
  };

  await expect(
    setCandidateExclusion({
      actorId: adminId,
      candidateId,
      excluded: false,
      signedAction: invalidAction
    })
  ).rejects.toThrow('Invalid administrator digital signature');

  expect((await getCandidate()).excluded).toBe(true);
});

test('a signed candidate-order change is stored correctly', async () => {
  const signedAction = makeSignedAction('candidate.order', '2');

  const outcome = await setCandidateOrder({
    actorId: adminId,
    candidateId,
    ballotOrder: 2,
    signedAction
  });

  expect(outcome.audited).toBe(true);
  expect((await getCandidate()).ballot_order).toBe(2);

  const evidence = await adminDb.query(
    `SELECT action, new_value
     FROM signed_candidate_actions
     WHERE candidate_id = $1
     ORDER BY id DESC LIMIT 1`,
    [candidateId]
  );

  expect(evidence.rowCount).toBe(1);
  expect(evidence.rows[0]).toMatchObject({
    action: 'candidate.order',
    new_value: '2'
  });
});

test('rejects an unsigned candidate-order change', async () => {
  await expect(
    setCandidateOrder({
      actorId: adminId,
      candidateId,
      ballotOrder: 5
    })
  ).rejects.toThrow('Missing or mismatched administrator signature');

  expect((await getCandidate()).ballot_order).toBe(2);
});

test('rejects a signature attributed to another administrator', async () => {
  const signedAction = makeSignedAction('candidate.order', '6');

  await expect(
    setCandidateOrder({
      actorId: adminId,
      candidateId,
      ballotOrder: 6,
      signedAction: {
        ...signedAction,
        adminId: adminId + 1
      }
    })
  ).rejects.toThrow('Missing or mismatched administrator signature');

  expect((await getCandidate()).ballot_order).toBe(2);
});

test('rejects a candidate change signed with an unregistered administrator key', async () => {
  const wrongKeyPair = crypto.generateKeyPairSync('ed25519');

  const forgedAction = signCandidateAction({
    adminId,
    candidateId,
    actionType: 'candidate.order',
    newValue: '7',
    signedAt: new Date().toISOString()
  }, wrongKeyPair.privateKey);

  expect(
    verifyCandidateAction(forgedAction, wrongKeyPair.publicKey)
  ).toBe(true);

  expect(
    verifyCandidateAction(forgedAction, publicKey)
  ).toBe(false);

  const beforeEvidence = await countSignedActions();

  await expect(
    setCandidateOrder({
      actorId: adminId,
      candidateId,
      ballotOrder: 7,
      signedAction: forgedAction
    })
  ).rejects.toThrow('Administrator signing key is not registered');

  expect((await getCandidate()).ballot_order).toBe(2);
  expect(await countSignedActions()).toBe(beforeEvidence);
});
