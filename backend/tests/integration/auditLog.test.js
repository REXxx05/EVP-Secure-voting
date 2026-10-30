
const crypto = require('crypto');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { signCandidateAction, keyIdOf } = require('../../src/security/adminSigning');
const { createAuditedRunner } = require('../../src/services/auditLog');
const { setCandidateExclusion } = require('../../src/services/adminActions');

jest.setTimeout(15000);

let adminId;
let voterId;
let auditorId;
let electionId;
let candidateId;
let testPrivateKey;

const runAudited = createAuditedRunner({ pool: db.pool });

function signedExclusion(excluded, id = candidateId) {
  return signCandidateAction({
    adminId,
    candidateId: id,
    actionType: excluded ? 'candidate.exclude' : 'candidate.restore',
    newValue: String(excluded),
    signedAt: new Date().toISOString()
  }, testPrivateKey);
}

function exclusionArgs(excluded, id = candidateId) {
  return {
    actorId: adminId,
    candidateId: id,
    excluded,
    signedAction: signedExclusion(excluded, id)
  };
}

async function addUser(role) {
  const result = await adminDb.query(
    `INSERT INTO users (username, password_hash, role)
     VALUES ($1, 'test-only-not-a-login', $2)
     RETURNING id`,
    [`sr15_${role}_${crypto.randomUUID()}`, role]
  );

  return result.rows[0].id;
}

async function rowsFor(actorIds) {
  const result = await adminDb.query(
    'SELECT * FROM audit_log WHERE actor_id = ANY($1) ORDER BY id',
    [actorIds]
  );

  return result.rows;
}

async function excludedNow() {
  const result = await adminDb.query(
    'SELECT excluded FROM candidates WHERE id = $1',
    [candidateId]
  );

  return result.rows[0].excluded;
}

beforeEach(async () => {
  adminId = await addUser('admin');

  const pair = crypto.generateKeyPairSync('ed25519');
  testPrivateKey = pair.privateKey;

  await adminDb.query(
    `INSERT INTO admin_signing_keys
       (admin_id, public_key_pem, key_id)
     VALUES ($1, $2, $3)`,
    [
      adminId,
      pair.publicKey.export({
        type: 'spki',
        format: 'pem'
      }),
      keyIdOf(pair.publicKey)
    ]
  );

  voterId = await addUser('voter');
  auditorId = await addUser('auditor');

  const election = await adminDb.query(
    `INSERT INTO elections (name, status)
     VALUES ($1, 'draft')
     RETURNING id`,
    [`SR15 isolated ${crypto.randomUUID()}`]
  );

  electionId = election.rows[0].id;

  const division = await adminDb.query(
    'SELECT id FROM divisions ORDER BY id LIMIT 1'
  );

  const divisionId = division.rows[0].id;

  const candidate = await adminDb.query(
    `INSERT INTO candidates
       (election_id, division_id, full_name, ballot_order)
     VALUES ($1, $2, 'Test Candidate', 1)
     RETURNING id`,
    [electionId, divisionId]
  );

  candidateId = candidate.rows[0].id;
});

// Keep fixtures in the disposable test database because
// signed candidate evidence is append-only.
afterAll(async () => {
  await db.pool.end();
  await adminDb.end();
});

test('a successful privileged action is audited within 1 second', async () => {
  const before = Date.now();

  const { result, audited } = await setCandidateExclusion(
    exclusionArgs(true),
    runAudited
  );

  const elapsed = Date.now() - before;

  expect(result).toEqual({
    candidateId,
    excluded: true
  });

  expect(elapsed).toBeLessThan(1000);
  expect(await excludedNow()).toBe(true);

  const [row] = await rowsFor([adminId]);

  expect(row).toMatchObject({
    actor_id: adminId,
    action: 'candidate.exclude',
    target: `candidate:${candidateId}`,
    outcome: 'success',
    detail: null
  });

  expect(row.occurred_at.getTime()).toBeGreaterThanOrEqual(
    before - 1000
  );

  expect(row.occurred_at.getTime()).toBeLessThanOrEqual(
    Date.now() + 1000
  );

  expect(row.occurred_at.toISOString()).toMatch(/Z$/);
  expect(audited).toBe(true);

  const utc = await adminDb.query(
    `SELECT to_char(
       occurred_at AT TIME ZONE 'UTC',
       'YYYY-MM-DD"T"HH24:MI:SS'
     ) AS t
     FROM audit_log
     WHERE id = $1`,
    [row.id]
  );

  expect(utc.rows[0].t).toBe(
    row.occurred_at.toISOString().slice(0, 19)
  );
});

test('a failed privileged action is rolled back and audited', async () => {
  await expect(
    setCandidateExclusion(
      exclusionArgs(true, 2147483000),
      runAudited
    )
  ).rejects.toThrow(
    /foreign key constraint|Candidate not found/
  );

  const rows = await rowsFor([adminId]);

  expect(rows).toHaveLength(1);

  expect(rows[0]).toMatchObject({
    actor_id: adminId,
    action: 'candidate.exclude',
    target: 'candidate:2147483000',
    outcome: 'failure',
    detail: 'action_error'
  });

  expect(rows[0].detail).not.toContain('Candidate');
});

test('a failed transaction leaves no candidate change', async () => {
  await expect(
    runAudited(
      {
        actorId: adminId,
        action: 'candidate.exclude',
        target: `candidate:${candidateId}`
      },
      async client => {
        await client.query(
          'UPDATE candidates SET excluded = TRUE WHERE id = $1',
          [candidateId]
        );

        throw new Error('boom after write');
      }
    )
  ).rejects.toThrow('boom after write');

  expect(await excludedNow()).toBe(false);

  expect(
    (await rowsFor([adminId])).map(row => row.outcome)
  ).toEqual(['failure']);
});

test.each(['voter', 'auditor'])(
  'unauthorised %s is blocked and audited',
  async role => {
    const actorId = role === 'voter'
      ? voterId
      : auditorId;

    await expect(
      setCandidateExclusion({
        actorId,
        candidateId,
        excluded: true
      }, runAudited)
    ).rejects.toMatchObject({
      code: 'FORBIDDEN'
    });

    expect(await excludedNow()).toBe(false);

    const rows = await rowsFor([actorId]);

    expect(rows).toHaveLength(1);

    expect(rows[0]).toMatchObject({
      actor_id: actorId,
      outcome: 'failure',
      detail: 'not_authorised',
      action: 'candidate.exclude',
      target: `candidate:${candidateId}`
    });
  }
);

test('roles can be widened for a particular action', async () => {
  const input = {
    actorId: auditorId,
    action: 'report.view',
    target: 'election:1',
    allowedRoles: ['admin', 'auditor']
  };

  await expect(
    runAudited(input, async () => 'ok')
  ).resolves.toMatchObject({
    result: 'ok'
  });

  expect(
    (await rowsFor([auditorId]))[0]
  ).toMatchObject({
    outcome: 'success',
    action: 'report.view'
  });
});

function poolFailingAudit({
  failTransactionalInsert = true,
  failStandaloneInsert = false
} = {}) {
  const isAudit = sql =>
    typeof sql === 'string' &&
    sql.includes('INSERT INTO audit_log');

  return {
    connect: async () => {
      const client = await db.pool.connect();

      return {
        query: (sql, params) =>
          failTransactionalInsert && isAudit(sql)
            ? Promise.reject(
                new Error('audit store unavailable')
              )
            : client.query(sql, params),

        release: discard => client.release(discard)
      };
    },

    query: (sql, params) =>
      failStandaloneInsert && isAudit(sql)
        ? Promise.reject(
            new Error('audit store unavailable')
          )
        : db.pool.query(sql, params)
  };
}

test('a failed audit write blocks the action and rolls it back', async () => {
  const blocked = createAuditedRunner({
    pool: poolFailingAudit()
  });

  const outcome = await setCandidateExclusion(
    exclusionArgs(true),
    blocked
  ).catch(error => error);

  expect(outcome).toMatchObject({
    name: 'AuditError',
    code: 'AUDIT_WRITE_FAILED'
  });

  expect(await excludedNow()).toBe(false);

  expect(
    (await rowsFor([adminId])).every(
      row => row.outcome === 'failure'
    )
  ).toBe(true);
});

test('a failed failure-audit write returns an audit error', async () => {
  const blocked = createAuditedRunner({
    pool: poolFailingAudit({
      failStandaloneInsert: true
    })
  });

  const outcome = await blocked(
    {
      actorId: voterId,
      action: 'candidate.exclude',
      target: `candidate:${candidateId}`
    },
    async () => 'should not run'
  ).catch(error => error);

  expect(outcome).toMatchObject({
    code: 'AUDIT_WRITE_FAILED'
  });

  expect(await excludedNow()).toBe(false);
});

test('an unknown actor is rejected', async () => {
  await expect(
    runAudited(
      {
        actorId: 2147483000,
        action: 'candidate.exclude',
        target: 'candidate:1'
      },
      async () => 'should not run'
    )
  ).rejects.toMatchObject({
    code: 'INVALID_ACTOR'
  });
});

test.each([
  [{ actorId: 'x', action: 'a.b', target: 't' }],
  [{ actorId: 1, action: 'Bad Action', target: 't' }],
  [{ actorId: 1, action: 'a.b', target: 'has space' }],
  [{ actorId: 1, action: 'a.b', target: '' }],
  [{ actorId: 1, action: 'a.b' }]
])('invalid audit input %j is refused', async input => {
  const work = jest.fn();

  await expect(
    runAudited(input, work)
  ).rejects.toMatchObject({
    code: 'INVALID_AUDIT_INPUT'
  });

  expect(work).not.toHaveBeenCalled();
});

test('audit records cannot be modified, deleted or read by the app', async () => {
  await setCandidateExclusion(
    exclusionArgs(true),
    runAudited
  );

  await expect(
    db.query(
      'UPDATE audit_log SET outcome = $1',
      ['failure']
    )
  ).rejects.toMatchObject({
    code: '42501'
  });

  await expect(
    db.query('DELETE FROM audit_log')
  ).rejects.toMatchObject({
    code: '42501'
  });

  await expect(
    db.query('SELECT * FROM audit_log')
  ).rejects.toMatchObject({
    code: '42501'
  });

  await expect(
    adminDb.query(
      'UPDATE audit_log SET outcome = $1 WHERE actor_id = $2',
      ['failure', adminId]
    )
  ).rejects.toThrow('append-only');

  await expect(
    adminDb.query(
      'DELETE FROM audit_log WHERE actor_id = $1',
      [adminId]
    )
  ).rejects.toThrow('append-only');

  await expect(
    adminDb.query('TRUNCATE audit_log')
  ).rejects.toThrow('append-only');

  expect(await rowsFor([adminId])).toHaveLength(1);
});

test('restoring a candidate creates a separate audit record', async () => {
  await setCandidateExclusion(
    exclusionArgs(true),
    runAudited
  );

  await setCandidateExclusion(
    exclusionArgs(false),
    runAudited
  );

  expect(
    (await rowsFor([adminId])).map(row => row.action)
  ).toEqual([
    'candidate.exclude',
    'candidate.restore'
  ]);

  expect(await excludedNow()).toBe(false);
});
