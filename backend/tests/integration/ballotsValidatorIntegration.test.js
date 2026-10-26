// SR-06 + SR-07: the real submission router and service with the REAL
// validateBallots (not a mock), real eligibility, anonymous storage, integrity
// hashes and receipts, against PostgreSQL.
//
// Only the SR-04 pieces are simulated, in this test only: authenticateVoter,
// verifyCsrf and invalidateSession. They are not production code and do not
// stand in for SR-04 behaviour. Everything else on the vote path is real.
//
// Required payload: { house: { ranking: [ids] }, senate: { ranking: [ids] } }
const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { purgeElectionBallots } = require('../helpers/fixtures');
const { createBallotsRouter } = require('../../src/routes/ballots');
const { validateBallots } = require('../../src/services/ballotValidator');
const { decrypt } = require('../../src/security/encryption');

jest.setTimeout(20000);

let voterId; let electionId; let tag;
const division = {}; // A, B (both VIC), C (NSW)
const cand = {};     // A1..A3, B1..B3, C1..C3

async function addDivision(key, state) {
  division[key] = (await adminDb.query(
    'INSERT INTO divisions (name, state) VALUES ($1, $2) RETURNING id',
    [`SR06 ${key} ${tag}`, state])).rows[0].id;
}
async function addCandidate(name, divisionKey, order) {
  cand[name] = (await adminDb.query(
    `INSERT INTO candidates (election_id, division_id, full_name, party, ballot_order)
     VALUES ($1, $2, $3, 'Test Party', $4) RETURNING id`,
    [electionId, division[divisionKey], name, order])).rows[0].id;
}

let spies;
function appWith() {
  spies = { invalidateSession: jest.fn(async () => true), validateBallots: jest.fn(validateBallots) };
  const app = express();
  app.use(express.json());
  app.use(createBallotsRouter({
    pool: db.pool,
    validateBallots: spies.validateBallots,                                   // REAL SR-07 validator, wrapped to observe the call
    authenticateVoter: (req, res, next) => {                                  // simulated SR-04, test only
      req.user = { id: voterId, role: 'voter' }; req.session = { id: 1 }; next();
    },
    verifyCsrf: (req, res, next) => next(),                                   // simulated SR-04, test only
    invalidateSession: spies.invalidateSession
  }));
  return app;
}
const post = (app, body) => request(app).post(`/api/elections/${electionId}/ballots`).send(body);

beforeEach(async () => {
  tag = crypto.randomUUID().slice(0, 8);
  await addDivision('A', 'VIC'); await addDivision('B', 'VIC'); await addDivision('C', 'NSW');
  electionId = (await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'open') RETURNING id", ['SR06 validator ' + tag])).rows[0].id;
  for (const [i, key] of ['A', 'B', 'C'].entries()) {
    for (let n = 1; n <= 3; n++) await addCandidate(`${key}${n}`, key, n + i * 10);
  }
  voterId = (await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'test-only-not-a-login', 'voter') RETURNING id",
    ['sr06v_' + tag])).rows[0].id;
  // the voter is enrolled in division A; the division comes from here, never the request
  await adminDb.query('INSERT INTO enrolments (user_id, election_id, division_id) VALUES ($1, $2, $3)',
    [voterId, electionId, division.A]);
});
afterEach(async () => {
  await purgeElectionBallots(electionId);
  await adminDb.query('DELETE FROM voter_participation WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM enrolments WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM candidates WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  await adminDb.query('DELETE FROM users WHERE id = $1', [voterId]);
  await adminDb.query('DELETE FROM divisions WHERE id = ANY($1)', [Object.values(division)]);
});
afterAll(async () => { await db.pool.end(); await adminDb.end(); });

// House: all 3 non-excluded candidates of the voter's division (A). Senate: 6 VIC candidates (A + B).
const validHouse = () => [cand.A2, cand.A1, cand.A3];
const validSenate = () => [cand.B1, cand.A1, cand.B2, cand.A2, cand.B3, cand.A3];
const validBody = () => ({ house: { ranking: validHouse() }, senate: { ranking: validSenate() } });

async function nothingPersisted() {
  const r = await adminDb.query(
    `SELECT (SELECT count(*)::int FROM voter_participation WHERE election_id = $1) AS p,
            (SELECT count(*)::int FROM ballots WHERE election_id = $1) AS b,
            (SELECT count(*)::int FROM bulletin_board WHERE election_id = $1) AS r`, [electionId]);
  expect(r.rows[0]).toEqual({ p: 0, b: 0, r: 0 });
}

test('a valid ranking payload is accepted: 201, receipt, both ballots stored as sent', async () => {
  const res = await post(appWith(), validBody());
  expect(res.status).toBe(201);
  expect(res.body.accepted).toBe(true);
  expect(res.body.receipt.verificationCode).toBeDefined();

  // the real validator received exactly the submitted ballots plus the server-derived division
  expect(spies.validateBallots).toHaveBeenCalledTimes(1);
  const arg = spies.validateBallots.mock.calls[0][0];
  expect(arg.house).toEqual({ ranking: validHouse() });
  expect(arg.senate).toEqual({ ranking: validSenate() });
  expect(arg.electionId).toBe(electionId);
  expect(arg.divisionId).toBe(division.A);
  expect(spies.invalidateSession).toHaveBeenCalledTimes(1);

  const stored = await adminDb.query(
    'SELECT ballot_type, ballot_data_enc FROM ballots WHERE election_id = $1', [electionId]);
  const byType = Object.fromEntries(stored.rows.map(r => [r.ballot_type, JSON.parse(decrypt(r.ballot_data_enc))]));
  expect(byType).toEqual({ house: { ranking: validHouse() }, senate: { ranking: validSenate() } });
});

test('duplicate candidate IDs are rejected (House and Senate) and nothing is saved', async () => {
  const app = appWith();
  const dupHouse = await post(app, { house: { ranking: [cand.A1, cand.A1, cand.A2, cand.A3] }, senate: { ranking: validSenate() } });
  expect(dupHouse.status).toBe(422);
  expect(dupHouse.body.code).toBe('INVALID_BALLOT');
  const dupSenate = await post(app, { house: { ranking: validHouse() },
    senate: { ranking: [cand.B1, cand.A1, cand.B2, cand.A2, cand.B3, cand.B3] } });
  expect(dupSenate.status).toBe(422);
  await nothingPersisted();
  expect(spies.invalidateSession).not.toHaveBeenCalled();
});

test('a House candidate from another division is rejected', async () => {
  const res = await post(appWith(), { house: { ranking: [cand.A1, cand.A2, cand.B1] }, senate: { ranking: validSenate() } });
  expect(res.status).toBe(422);
  await nothingPersisted();
});

test('a House ballot that leaves out a candidate of the voter\'s division is rejected', async () => {
  const res = await post(appWith(), { house: { ranking: [cand.A1, cand.A2] }, senate: { ranking: validSenate() } });
  expect(res.status).toBe(422);
  await nothingPersisted();
});

test('a Senate candidate from another state is rejected', async () => {
  const res = await post(appWith(), { house: { ranking: validHouse() },
    senate: { ranking: [cand.B1, cand.A1, cand.B2, cand.A2, cand.B3, cand.C1] } });
  expect(res.status).toBe(422);
  await nothingPersisted();
});

test('a Senate ballot with fewer than 6 candidates is rejected', async () => {
  const res = await post(appWith(), { house: { ranking: validHouse() }, senate: { ranking: [cand.B1, cand.A1, cand.B2, cand.A2, cand.B3] } });
  expect(res.status).toBe(422);
  await nothingPersisted();
});

test('extra fields inside a ballot are rejected by the real validator', async () => {
  const app = appWith();
  const extraHouse = await post(app, { house: { ranking: validHouse(), note: 'x' }, senate: { ranking: validSenate() } });
  expect(extraHouse.status).toBe(422);
  const extraSenate = await post(app, { house: { ranking: validHouse() }, senate: { ranking: validSenate(), above: [1] } });
  expect(extraSenate.status).toBe(422);
  await nothingPersisted();
});

test('extra top-level fields are rejected before validation or any database work', async () => {
  const app = appWith();
  const res = await post(app, { ...validBody(), divisionId: division.B });
  expect(res.status).toBe(400);
  expect(spies.validateBallots).not.toHaveBeenCalled();
  await nothingPersisted();
});

test('the old placeholder shapes are rejected', async () => {
  const res = await post(appWith(), { house: { preferences: validHouse() }, senate: { above: validSenate() } });
  expect(res.status).toBe(422);
  await nothingPersisted();
});

test('IDs must be integers (text and decimals rejected)', async () => {
  const app = appWith();
  expect((await post(app, { house: { ranking: ['1', '2', '3'] }, senate: { ranking: validSenate() } })).status).toBe(422);
  expect((await post(app, { house: { ranking: [1.5, 2, 3] }, senate: { ranking: validSenate() } })).status).toBe(422);
  await nothingPersisted();
});

test('after a rejected ballot the voter can still submit a valid one, then a repeat gets 409', async () => {
  const app = appWith();
  expect((await post(app, { house: { ranking: [cand.A1] }, senate: { ranking: validSenate() } })).status).toBe(422);
  expect((await post(app, validBody())).status).toBe(201);
  const again = await post(app, validBody());
  expect(again.status).toBe(409);
  expect(again.body.code).toBe('ALREADY_VOTED');
});
