// SR-16: Automated audit hash-chain integrity tests.
// Uses mocked database responses; does not modify PostgreSQL.

const {
  verifyAuditIntegrity,
  GENESIS_HASH
} = require('../../src/services/auditIntegrity');

const {
  recordAuditIntegrityAlert
} = require('../../src/services/auditIntegrityAlerts');

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);

function createMockDb(records, head) {
  return {
    query: jest.fn(async (sql) => {
      const statement = sql.trim();

      if (statement.startsWith('BEGIN')) {
        return { rows: [] };
      }

      if (statement.startsWith('SELECT') &&
          statement.includes('FROM public.audit_log')) {
        return { rows: records };
      }

      if (statement.startsWith('SELECT') &&
          statement.includes('FROM public.audit_chain_state')) {
        return {
          rows: [{ last_hash: head }]
        };
      }

      if (statement === 'COMMIT' || statement === 'ROLLBACK') {
        return { rows: [] };
      }

      throw new Error(`Unexpected database query: ${statement}`);
    })
  };
}

describe('SR-16: Audit hash-chain integrity', () => {

  test('Accepts an empty audit log with the genesis hash', async () => {
    const db = createMockDb([], GENESIS_HASH);

    const result = await verifyAuditIntegrity(db);

    expect(result).toEqual({
      valid: true,
      checkedRecords: 0,
      issues: []
    });
  });

  test('Accepts a valid two-record hash chain', async () => {
    const records = [
      {
        id: 1,
        previous_hash: GENESIS_HASH,
        entry_hash: HASH_A,
        expected_hash: HASH_A
      },
      {
        id: 2,
        previous_hash: HASH_A,
        entry_hash: HASH_B,
        expected_hash: HASH_B
      }
    ];

    const db = createMockDb(records, HASH_B);

    const result = await verifyAuditIntegrity(db);

    expect(result.valid).toBe(true);
    expect(result.checkedRecords).toBe(2);
    expect(result.issues).toEqual([]);
  });

  test('Detects a modified audit record', async () => {
    const records = [
      {
        id: 1,
        previous_hash: GENESIS_HASH,
        entry_hash: HASH_A,
        expected_hash: HASH_C
      }
    ];

    const db = createMockDb(records, HASH_A);

    const result = await verifyAuditIntegrity(db);

    expect(result.valid).toBe(false);
    expect(result.issues).toContain(
      'Audit record 1 has an invalid hash'
    );
  });

  test('Detects a missing audit record', async () => {
    const records = [
      {
        id: 1,
        previous_hash: GENESIS_HASH,
        entry_hash: HASH_A,
        expected_hash: HASH_A
      }
    ];

    // The chain head points to a missing second record.
    const db = createMockDb(records, HASH_B);

    const result = await verifyAuditIntegrity(db);

    expect(result.valid).toBe(false);
    expect(result.issues.some(
      issue => issue.includes('Missing audit record')
    )).toBe(true);
  });

  test('Detects an incorrect stored chain head', async () => {
    const records = [
      {
        id: 1,
        previous_hash: GENESIS_HASH,
        entry_hash: HASH_A,
        expected_hash: HASH_A
      }
    ];

    const db = createMockDb(records, GENESIS_HASH);

    const result = await verifyAuditIntegrity(db);

    expect(result.valid).toBe(false);
    expect(result.issues.some(
      issue => issue.includes('linked records')
    )).toBe(true);
  });

  test('Detects duplicate audit hashes', async () => {
    const records = [
      {
        id: 1,
        previous_hash: GENESIS_HASH,
        entry_hash: HASH_A,
        expected_hash: HASH_A
      },
      {
        id: 2,
        previous_hash: GENESIS_HASH,
        entry_hash: HASH_A,
        expected_hash: HASH_A
      }
    ];

    const db = createMockDb(records, HASH_A);

    const result = await verifyAuditIntegrity(db);

    expect(result.valid).toBe(false);
    expect(result.issues.some(
      issue => issue.includes('Duplicate audit hash')
    )).toBe(true);
  });

  test('Detects a cycle in the audit chain', async () => {
    const records = [
      {
        id: 1,
        previous_hash: HASH_B,
        entry_hash: HASH_A,
        expected_hash: HASH_A
      },
      {
        id: 2,
        previous_hash: HASH_A,
        entry_hash: HASH_B,
        expected_hash: HASH_B
      }
    ];

    const db = createMockDb(records, HASH_B);

    const result = await verifyAuditIntegrity(db);

    expect(result.valid).toBe(false);
    expect(result.issues).toContain(
      'Cycle detected in the audit hash chain'
    );
  });

});

describe('SR-16: Integrity alert generation', () => {

  test('Does not create an alert for a valid chain', async () => {
    const db = {
      query: jest.fn()
    };

    const result = await recordAuditIntegrityAlert(db, {
      valid: true,
      checkedRecords: 2,
      issues: []
    });

    expect(result).toBeNull();
    expect(db.query).not.toHaveBeenCalled();
  });

  test('Creates an alert when audit tampering is detected', async () => {
    const db = {
      query: jest.fn().mockResolvedValue({
        rows: [{
          id: 10,
          issue_count: 1,
          checked_records: 1
        }]
      })
    };

    const verification = {
      valid: false,
      checkedRecords: 1,
      issues: ['Audit record 1 has an invalid hash']
    };

    const alert = await recordAuditIntegrityAlert(db, verification);

    expect(alert.id).toBe(10);
    expect(alert.issue_count).toBe(1);
    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, parameters] = db.query.mock.calls[0];

    expect(sql).toContain('INSERT INTO public.audit_integrity_alerts');
    expect(parameters[0]).toBe(1);
    expect(parameters[1]).toBe(1);
    expect(JSON.parse(parameters[2])).toEqual({
      issues: ['Audit record 1 has an invalid hash']
    });
  });

});