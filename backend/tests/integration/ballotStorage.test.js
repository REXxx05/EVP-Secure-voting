// Tests for SR-08 (voter anonymity).
// Every test runs in a transaction that we ROLLBACK at the end,
// so no test data is left behind in the database.

const db = require('../../src/config/db');
const { saveBallotAnonymously } = require('../../src/services/ballotStorage');
const { decrypt } = require('../../src/security/encryption');

let client;

// before each test: grab a connection and start a transaction
beforeEach(async () => {
  client = await db.pool.connect();
  await client.query('BEGIN');
});

// after each test: undo everything the test did
afterEach(async () => {
  await client.query('ROLLBACK');
  client.release();
});

afterAll(async () => {
  await db.pool.end();
});

// a sample House ballot (preferences for candidates 2, 1 and 3)
const sampleBallot = {
  electionId: 1,
  divisionId: 1,
  ballotType: 'house',
  ballotData: { preferences: [2, 1, 3] }
};

describe('SR-08 voter anonymity', () => {

  test('saves a ballot and gives back a random id', async () => {
    const ballotId = await saveBallotAnonymously(client, sampleBallot);

    // should look like a UUID, e.g. 3f2b...-....-....
    expect(ballotId).toMatch(/^[0-9a-f-]{36}$/);
  });

  test('ballot is stored encrypted, not as plain text', async () => {
    const ballotId = await saveBallotAnonymously(client, sampleBallot);

    const result = await client.query('SELECT ballot_data_enc FROM ballots WHERE id = $1', [ballotId]);
    const stored = result.rows[0].ballot_data_enc;

    // the raw value in the database shouldn't show the votes
    expect(stored).not.toContain('preferences');

    // but we can still decrypt it back to the original when counting
    expect(JSON.parse(decrypt(stored))).toEqual({ preferences: [2, 1, 3] });
  });

  test('ballots table has no columns that could identify the voter', async () => {
    const result = await client.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = 'ballots' ORDER BY column_name`
    );
    const columns = result.rows.map((row) => row.column_name);

    // these are the only columns allowed. No user id, no timestamps.
    expect(columns).toEqual([
      'ballot_data_enc', 'ballot_type', 'division_id', 'election_id', 'id', 'key_version'
    ]);
  });

  test('app is not allowed to read who has voted', async () => {
    await expect(client.query('SELECT * FROM voter_participation'))
      .rejects.toThrow('permission denied');
  });

  test('has_voted() says yes or no for one voter', async () => {
    // make a fake voter and mark them as voted (all rolled back after)
    const user = await client.query(
      "INSERT INTO users (username, password_hash, role) VALUES ('anon_test_voter', 'not-a-real-hash', 'voter') RETURNING id"
    );
    const userId = user.rows[0].id;
    await client.query('INSERT INTO voter_participation (user_id, election_id) VALUES ($1, 1)', [userId]);

    const voted = await client.query('SELECT has_voted($1, 1) AS result', [userId]);
    expect(voted.rows[0].result).toBe(true);

    const notVoted = await client.query('SELECT has_voted($1, 1) AS result', [999999]);
    expect(notVoted.rows[0].result).toBe(false);
  });

  test('rejects a ballot type that is not house or senate', async () => {
    const badBallot = { ...sampleBallot, ballotType: 'mayor' };
    await expect(saveBallotAnonymously(client, badBallot)).rejects.toThrow('Invalid ballot type');
  });

});