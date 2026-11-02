// SR-16: Scheduled audit-log integrity verification.

const path = require('path');
const { Pool } = require('pg');

require('dotenv').config({
  path: path.resolve(__dirname, '../../.env'),
  quiet: true
});

const { verifyAuditIntegrity } = require('../src/services/auditIntegrity');
const { recordAuditIntegrityAlert } = require('../src/services/auditIntegrityAlerts');

async function main() {
  // Require explicit checker credentials rather than using the
  // application's database account or test-only admin connection.
  const user = process.env.AUDIT_CHECKER_DB_USER;
  const password = process.env.AUDIT_CHECKER_DB_PASSWORD;

  if (!user || !password) {
    throw new Error('Audit checker database credentials are not configured');
  }

  const db = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user,
    password
  });

  try {
    const result = await verifyAuditIntegrity(db);

    if (result.valid) {
      console.log(`[${new Date().toISOString()}] Audit integrity: PASS`);
      console.log(`Checked ${result.checkedRecords} records.`);
      return;
    }

    const alert = await recordAuditIntegrityAlert(db, result);

    console.error(`[${new Date().toISOString()}] Audit integrity: FAILED`);
    console.error(`Alert ID: ${alert.id}`);
    console.error(result.issues.join('\n'));

    process.exitCode = 1;
  } finally {
    await db.end();
  }
}

main().catch(error => {
  console.error('Audit integrity check could not complete:', error.message);
  process.exitCode = 1;
});