// SR-13: Unit tests for ballot reconciliation.

const {
  reconcileElection
} = require('../../src/services/ballotReconciliation');

function createMockPool({
  status = 'closed',
  submissions = 2,
  ballots = 4,
  house = 2,
  senate = 2,
  hashes = 4,
  hashElectionMismatches = 0,
  receipts = 2,
  integrityOk = true,
  verifiedBallots = 4,
  alertFails = false
} = {}) {

  const client = {
    query: jest.fn(async sql => {

      if (sql.startsWith('BEGIN')) return {};
      if (sql === 'COMMIT' || sql === 'ROLLBACK') return {};

      if (sql.includes('SELECT status FROM public.elections')) {
        return {
          rowCount: 1,
          rows: [{ status }]
        };
      }

      if (sql.includes('count_accepted_submissions')) {
        return {
          rows: [{ count: String(submissions) }]
        };
      }

      // House and Senate ballot counts.
      if (
        sql.includes('house_count') &&
        sql.includes('senate_count')
      ) {
        return {
          rows: [{
            house_count: String(house),
            senate_count: String(senate)
          }]
        };
      }

      // Hash records linked to another election.
      if (
        sql.includes('JOIN public.ballots b') &&
        sql.includes('h.election_id <> b.election_id')
      ) {
        return {
          rows: [{
            count: String(hashElectionMismatches)
          }]
        };
      }

      if (
        sql.includes('COUNT(*)') &&
        sql.includes('FROM public.ballots')
      ) {
        return {
          rows: [{ count: String(ballots) }]
        };
      }

      if (
        sql.includes('COUNT(*)') &&
        sql.includes('FROM public.ballot_hashes')
      ) {
        return {
          rows: [{ count: String(hashes) }]
        };
      }

      if (
        sql.includes('COUNT(*)') &&
        sql.includes('FROM public.bulletin_board')
      ) {
        return {
          rows: [{ count: String(receipts) }]
        };
      }

      throw new Error(`Unexpected SQL: ${sql}`);
    }),

    release: jest.fn()
  };

  const pool = {
    connect: jest.fn(async () => client),

    query: jest.fn(async () => {
      if (alertFails) {
        throw new Error('Alert insertion failed');
      }

      return { rowCount: 1 };
    })
  };

  const verified = Array.from(
    { length: verifiedBallots },
    (_, index) => ({
      id: `ballot-${index + 1}`
    })
  );

  const verify = jest.fn(async () => ({
    ok: integrityOk,
    ballots: verified,
    mismatches: integrityOk
      ? []
      : [{ reason: 'hash_mismatch' }]
  }));

  return {
    pool,
    client,
    verify
  };
}

describe('SR-13 ballot reconciliation', () => {

  test('passes when all counts and integrity checks agree', async () => {
    const { pool, client, verify } = createMockPool();

    const result = await reconcileElection(1, {
      pool,
      verify
    });

    expect(result.ok).toBe(true);

    expect(result.counts).toEqual({
      acceptedSubmissions: 2,
      expectedBallots: 4,
      storedBallots: 4,
      houseBallots: 2,
      senateBallots: 2,
      hashEntries: 4,
      hashElectionMismatches: 0,
      verifiedTallyInputs: 4,
      receiptEntries: 2
    });

    expect(result.ballots).toHaveLength(4);

    expect(pool.query).not.toHaveBeenCalled();

    expect(client.query).toHaveBeenCalledWith(
      'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'
    );

    expect(client.query).toHaveBeenCalledWith('COMMIT');
    expect(client.release).toHaveBeenCalled();
  });

  test('rejects an invalid election ID', async () => {
    const { pool, verify } = createMockPool();

    await expect(
      reconcileElection(0, { pool, verify })
    ).rejects.toMatchObject({
      code: 'INVALID_ELECTION'
    });

    expect(pool.connect).not.toHaveBeenCalled();
  });

  test('blocks reconciliation while the election is open', async () => {
    const { pool, verify } = createMockPool({
      status: 'open'
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'ELECTION_NOT_CLOSED'
    });

    expect(verify).not.toHaveBeenCalled();
  });

  test('detects a total ballot count mismatch', async () => {
    const { pool, verify } = createMockPool({
      ballots: 3
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining(
        'INSERT INTO public.election_security_alerts'
      ),
      [1, 'reconciliation_failed', 'ballot_count_mismatch']
    );
  });

  test('detects missing House ballots', async () => {
    const { pool, verify } = createMockPool({
      house: 1,
      senate: 3
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'ballot_count_mismatch']
    );
  });

  test('detects missing Senate ballots', async () => {
    const { pool, verify } = createMockPool({
      house: 3,
      senate: 1
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'ballot_count_mismatch']
    );
  });

  test('detects a hash count mismatch', async () => {
    const { pool, verify } = createMockPool({
      hashes: 3
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'hash_count_mismatch']
    );
  });

  test('detects hashes linked to another election', async () => {
    const { pool, verify } = createMockPool({
      hashElectionMismatches: 1
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'hash_count_mismatch']
    );
  });

  test('detects a receipt count mismatch', async () => {
    const { pool, verify } = createMockPool({
      receipts: 1
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'receipt_count_mismatch']
    );
  });

  test('detects a cryptographic integrity failure', async () => {
    const { pool, verify } = createMockPool({
      integrityOk: false
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'integrity_failure']
    );
  });

  test('detects missing verified tally inputs', async () => {
    const { pool, verify } = createMockPool({
      verifiedBallots: 3
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });

    expect(pool.query).toHaveBeenCalledWith(
      expect.any(String),
      [1, 'reconciliation_failed', 'tally_count_mismatch']
    );
  });

  test('fails closed if the auditor alert cannot be recorded', async () => {
    const { pool, verify } = createMockPool({
      hashes: 3,
      alertFails: true
    });

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toMatchObject({
      code: 'ALERT_WRITE_FAILED'
    });
  });

  test('rolls back and releases the connection on database errors', async () => {
    const { pool, client, verify } = createMockPool();

    verify.mockRejectedValue(
      new Error('Database verification failed')
    );

    await expect(
      reconcileElection(1, { pool, verify })
    ).rejects.toThrow('Database verification failed');

    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    expect(client.release).toHaveBeenCalled();
  });

});