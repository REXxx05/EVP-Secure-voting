// SR-15: privileged administrator operations, each run through the audit log.
// Role checks beyond "must be an admin" (SR-03) and signing (SR-18) belong to
// their own requirements; this is where audited privileged operations live.
const { createAuditedRunner } = require('./auditLog');

const defaultRunner = createAuditedRunner();

// Exclude (or restore) a candidate. Returns { result: { candidateId, excluded }, audited: true }.
async function setCandidateExclusion(
  { actorId, candidateId, excluded }, runAuditedAction = defaultRunner
) {
  if (!Number.isSafeInteger(candidateId) || candidateId < 1 || typeof excluded !== 'boolean') {
    throw new TypeError('A valid candidate id and boolean excluded flag are required');
  }
  return runAuditedAction(
    { actorId, action: excluded ? 'candidate.exclude' : 'candidate.restore', target: `candidate:${candidateId}` },
    async client => {
      const updated = await client.query(
        'UPDATE candidates SET excluded = $1 WHERE id = $2 RETURNING id',
        [excluded, candidateId]
      );
      if (updated.rowCount !== 1) {
        throw new Error('Candidate not found');
      }
      return { candidateId, excluded };
    }
  );
}

module.exports = { setCandidateExclusion };
