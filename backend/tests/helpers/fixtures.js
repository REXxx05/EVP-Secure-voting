// Test-only cleanup. ballot_hashes (SR-11) is append-only for everyone, so the
// admin test connection switches triggers off for this one transaction
// (session_replication_role = replica) and deletes only rows of the given
// generated election fixture.
const adminDb = require('./adminDb');

async function purgeElectionBallots(electionId) {
  const client = await adminDb.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query('DELETE FROM bulletin_board WHERE election_id = $1', [electionId]);
    await client.query('DELETE FROM ballot_hashes WHERE election_id = $1', [electionId]);
    await client.query('DELETE FROM ballots WHERE election_id = $1', [electionId]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// audit_log is append-only too, so remove a generated admin's audit rows the same way
async function purgeAuditRows(actorIds) {
  const client = await adminDb.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query('DELETE FROM audit_log WHERE actor_id = ANY($1)', [actorIds]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { purgeElectionBallots, purgeAuditRows };
