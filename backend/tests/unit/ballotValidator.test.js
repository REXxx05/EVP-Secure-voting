// SR-07: unit tests for validateBallots. The database client is faked:
// the first query returns the voter's division candidates (House),
// the second returns the state's candidates (Senate).

const { validateBallots } = require('../../src/services/ballotValidator');

const HOUSE_CANDIDATES = [1, 2, 3];
const SENATE_CANDIDATES = [1, 2, 3, 4, 5, 6, 7];

function makeClient() {
  return {
    query: jest
      .fn()
      .mockResolvedValueOnce({ rows: HOUSE_CANDIDATES.map((id) => ({ id })) })
      .mockResolvedValueOnce({ rows: SENATE_CANDIDATES.map((id) => ({ id })) }),
  };
}

function run(overrides = {}, client = makeClient()) {
  return validateBallots({
    client,
    electionId: 1,
    divisionId: 1,
    house: { ranking: [3, 1, 2] },
    senate: { ranking: [7, 1, 2, 3, 4, 5] },
    ...overrides,
  }).then((result) => ({ result, client }));
}

describe('validateBallots (SR-07)', () => {
  test('accepts a valid House and Senate ballot', async () => {
    const { result } = await run();
    expect(result).toBe(true);
  });

  test('rejects a House ballot that leaves out a candidate', async () => {
    const { result } = await run({ house: { ranking: [1, 2] } });
    expect(result).toBe(false);
  });

  test('rejects a House ballot with a candidate from another division', async () => {
    const { result } = await run({ house: { ranking: [1, 2, 99] } });
    expect(result).toBe(false);
  });

  test('rejects a Senate ballot with fewer than 6 preferences before touching the database', async () => {
    const { result, client } = await run({ senate: { ranking: [1, 2, 3] } });
    expect(result).toBe(false);
    expect(client.query).not.toHaveBeenCalled();
  });

  test('rejects a Senate ballot with a candidate from another state', async () => {
    const { result } = await run({ senate: { ranking: [1, 2, 3, 4, 5, 99] } });
    expect(result).toBe(false);
  });

  test('rejects duplicate candidates', async () => {
    const { result, client } = await run({ house: { ranking: [1, 1, 2] } });
    expect(result).toBe(false);
    expect(client.query).not.toHaveBeenCalled();
  });

  test('rejects unexpected extra fields', async () => {
    const { result } = await run({ house: { ranking: [3, 1, 2], isAdmin: true } });
    expect(result).toBe(false);
  });

  test('rejects text, decimals, zero and negative ids without a database call', async () => {
    const bad = [
      ['1; DROP TABLE ballots', 2, 3],
      [1.5, 2, 3],
      [0, 1, 2],
      [-1, 2, 3],
    ];
    for (const ranking of bad) {
      const { result, client } = await run({ house: { ranking } });
      expect(result).toBe(false);
      expect(client.query).not.toHaveBeenCalled();
    }
  });

  test('rejects an oversized ranking', async () => {
    const huge = Array.from({ length: 101 }, (_, i) => i + 1);
    const { result, client } = await run({ senate: { ranking: huge } });
    expect(result).toBe(false);
    expect(client.query).not.toHaveBeenCalled();
  });

  test('rejects missing or wrongly-typed ballots', async () => {
    expect((await run({ house: undefined })).result).toBe(false);
    expect((await run({ senate: null })).result).toBe(false);
    expect((await run({ house: [1, 2, 3] })).result).toBe(false);
    expect((await run({ senate: 'all' })).result).toBe(false);
  });

  test('rejects an invalid election or division id', async () => {
    expect((await run({ electionId: 0 })).result).toBe(false);
    expect((await run({ divisionId: '1' })).result).toBe(false);
  });

  test('fails closed when the database errors', async () => {
    const client = { query: jest.fn().mockRejectedValue(new Error('db down')) };
    await expect(run({}, client)).rejects.toThrow('db down');
  });
});