// SR-07: validateBallots against the real database, connecting as the
// app's limited user (the same one the ballot submission flow uses).
// Fake data is created with the admin pool and removed afterwards.

const pool = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { validateBallots } = require('../../src/services/ballotValidator');

let electionId;
const divisionIds = {};
const ids = {}; // name -> candidate id
let client;

async function addDivision(key, state) {
  const result = await adminDb.query(
    'INSERT INTO divisions (name, state) VALUES ($1, $2) RETURNING id',
    [`SR07 ${key} ${Date.now()}`, state]
  );
  divisionIds[key] = result.rows[0].id;
}

async function addCandidate(name, divisionKey, order, excluded = false) {
  const result = await adminDb.query(
    `INSERT INTO candidates (election_id, division_id, full_name, party, ballot_order, excluded)
     VALUES ($1, $2, $3, 'Test Party', $4, $5) RETURNING id`,
    [electionId, divisionIds[divisionKey], name, order, excluded]
  );
  ids[name] = result.rows[0].id;
}

function check(house, senate) {
  return validateBallots({
    client,
    electionId,
    divisionId: divisionIds.A,
    house: { ranking: house },
    senate: { ranking: senate },
  });
}

beforeAll(async () => {
  const election = await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'draft') RETURNING id",
    [`SR07 test election ${Date.now()}`]
  );
  electionId = election.rows[0].id;

  await addDivision('A', 'VIC'); // the voter's division
  await addDivision('B', 'VIC'); // same state, different division
  await addDivision('C', 'NSW'); // different state

  await addCandidate('A1', 'A', 1);
  await addCandidate('A2', 'A', 2);
  await addCandidate('A3', 'A', 3);
  await addCandidate('A4x', 'A', 4, true); // excluded
  await addCandidate('B1', 'B', 1);
  await addCandidate('B2', 'B', 2);
  await addCandidate('B3', 'B', 3);
  await addCandidate('B4', 'B', 4);
  await addCandidate('C1', 'C', 1);

  client = await pool.pool.connect();
});

afterAll(async () => {
  client.release();
  await adminDb.query('DELETE FROM candidates WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM divisions WHERE id = ANY($1)', [Object.values(divisionIds)]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  await adminDb.end();
  await pool.pool.end();
});

describe('SR-07 ballot validation against the database', () => {
  // Valid Senate: 6 of the 7 non-excluded Victorian candidates
  const validSenate = () => [ids.A1, ids.A2, ids.A3, ids.B1, ids.B2, ids.B3];
  const validHouse = () => [ids.A3, ids.A1, ids.A2];

  test('accepts a correct House and Senate ballot', async () => {
    expect(await check(validHouse(), validSenate())).toBe(true);
  });

  test('rejects a House ballot that skips a candidate', async () => {
    expect(await check([ids.A1, ids.A2], validSenate())).toBe(false);
  });

  test('rejects a House ballot that ranks an excluded candidate', async () => {
    expect(await check([ids.A1, ids.A2, ids.A3, ids.A4x], validSenate())).toBe(false);
  });

  test('rejects a House ballot with a candidate from another division', async () => {
    expect(await check([ids.A1, ids.A2, ids.B1], validSenate())).toBe(false);
  });

  test('rejects a Senate ballot with a candidate from another state', async () => {
    const senate = [ids.A1, ids.A2, ids.A3, ids.B1, ids.B2, ids.C1];
    expect(await check(validHouse(), senate)).toBe(false);
  });

  test('rejects a Senate ballot that ranks an excluded candidate', async () => {
    const senate = [ids.A1, ids.A2, ids.A3, ids.B1, ids.B2, ids.A4x];
    expect(await check(validHouse(), senate)).toBe(false);
  });

  test('rejects injection-style input and leaves the data untouched', async () => {
    const before = await adminDb.query('SELECT count(*)::int AS n FROM candidates WHERE election_id = $1', [electionId]);
    const evil = ["1; DROP TABLE candidates; --", ids.A2, ids.A3];
    expect(await check(evil, validSenate())).toBe(false);
    const after = await adminDb.query('SELECT count(*)::int AS n FROM candidates WHERE election_id = $1', [electionId]);
    expect(after.rows[0].n).toBe(before.rows[0].n);
  });
});