// SR-16: Store alerts when audit-log integrity verification fails.

async function recordAuditIntegrityAlert(db, result) {
  if (!db || typeof db.query !== 'function') {
    throw new Error('A database connection is required');
  }

  if (!result || typeof result.valid !== 'boolean') {
    throw new Error('An integrity verification result is required');
  }

  // A valid audit chain does not require an alert.
  if (result.valid) {
    return null;
  }

  const issues = result.issues || [];

  if (issues.length === 0) {
    throw new Error('An invalid audit chain must include an issue');
  }

  const response = await db.query(
    `
      INSERT INTO public.audit_integrity_alerts
        (issue_count, checked_records, details)
      VALUES ($1, $2, $3::jsonb)
      RETURNING id, detected_at, issue_count, checked_records
    `,
    [
      issues.length,
      result.checkedRecords,
      JSON.stringify({ issues })
    ]
  );

  return response.rows[0];
}

module.exports = { recordAuditIntegrityAlert };