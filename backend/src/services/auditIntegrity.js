// SR-16: Verify the integrity of the append-only audit log.
//
// This service does not modify audit records.
// It checks record hashes, chain links, and the stored chain head.

const GENESIS_HASH = '0'.repeat(64);

async function verifyAuditIntegrity(db) {
  if (!db || typeof db.query !== 'function') {
    throw new Error('A database connection is required');
  }

  // Use one consistent database snapshot for the entire check.
  const client = typeof db.connect === 'function'
    ? await db.connect()
    : db;

  const shouldRelease = client !== db;

  try {
    await client.query(
      'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'
    );

    const recordsResult = await client.query(`
      SELECT
        id,
        previous_hash,
        entry_hash,
        public.calculate_audit_hash(
          previous_hash,
          id,
          actor_id,
          action,
          target,
          outcome,
          detail,
          occurred_at
        ) AS expected_hash
      FROM public.audit_log
    `);

    const stateResult = await client.query(`
      SELECT last_hash
      FROM public.audit_chain_state
      WHERE singleton = TRUE
    `);

    await client.query('COMMIT');

    const records = recordsResult.rows;
    const issues = [];

    if (stateResult.rows.length !== 1) {
      issues.push('Audit chain state is missing or invalid');

      return {
        valid: false,
        checkedRecords: records.length,
        issues
      };
    }

    const storedHead = stateResult.rows[0].last_hash;

    // Verify each record's stored SHA-256 hash.
    for (const record of records) {
      if (record.entry_hash !== record.expected_hash) {
        issues.push(`Audit record ${record.id} has an invalid hash`);
      }
    }

    // Build a lookup table using the stored hashes.
    const byHash = new Map();

    for (const record of records) {
      if (byHash.has(record.entry_hash)) {
        issues.push(
          `Duplicate audit hash detected: ${record.entry_hash}`
        );
      }

      byHash.set(record.entry_hash, record);
    }

    // Walk backwards from the stored chain head.
    const visited = new Set();
    let currentHash = storedHead;

    while (currentHash !== GENESIS_HASH) {
      if (visited.has(currentHash)) {
        issues.push('Cycle detected in the audit hash chain');
        break;
      }

      const record = byHash.get(currentHash);

      if (!record) {
        issues.push(`Missing audit record for hash ${currentHash}`);
        break;
      }

      // Count only records that actually exist.
      visited.add(currentHash);

      currentHash = record.previous_hash;
    }

    // Every stored record must belong to the chain.
    if (visited.size !== records.length) {
      issues.push(
        `Audit chain contains ${visited.size} linked records, ` +
        `but ${records.length} records exist`
      );
    }

    return {
      valid: issues.length === 0,
      checkedRecords: records.length,
      issues
    };

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {
      // Preserve the original error.
    }

    throw error;

  } finally {
    if (shouldRelease) {
      client.release();
    }
  }
}

module.exports = {
  verifyAuditIntegrity,
  GENESIS_HASH
};