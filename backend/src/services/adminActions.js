
/**
 * SR-15 / SR-18:
 * Audited and digitally signed candidate administration.
 */

const { createAuditedRunner } = require('./auditLog');
const {
  verifyCandidateAction
} = require('../security/adminSigning');

const defaultRunner = createAuditedRunner();

function validId(value) {
  return Number.isSafeInteger(value) && value > 0;
}

/**
 * Verify the administrator's signature using their registered
 * public key, then save the signed evidence.
 *
 * Must be called inside the same transaction as the candidate update.
 */
async function storeSignedAction(client, action) {
  const {
    adminId,
    candidateId,
    actionType,
    newValue,
    signedAt,
    keyId,
    signature
  } = action;

  const keyResult = await client.query(
    `SELECT id, public_key_pem
     FROM admin_signing_keys
     WHERE admin_id = $1
       AND key_id = $2
       AND revoked_at IS NULL`,
    [adminId, keyId]
  );

  if (keyResult.rowCount !== 1) {
    throw new Error('Administrator signing key is not registered');
  }

  if (
    !verifyCandidateAction(
      action,
      keyResult.rows[0].public_key_pem
    )
  ) {
    throw new Error('Invalid administrator digital signature');
  }

  await client.query(
    `INSERT INTO signed_candidate_actions
       (admin_id, candidate_id, action, new_value,
        signed_at, signing_key_id, signature)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      adminId,
      candidateId,
      actionType,
      newValue,
      signedAt,
      keyResult.rows[0].id,
      signature
    ]
  );
}

/**
 * Exclude or restore a candidate.
 *
 * The signature must belong to the acting administrator.
 */
async function setCandidateExclusion(
  {
    actorId,
    candidateId,
    excluded,
    signedAction
  },
  runAuditedAction = defaultRunner
) {
  if (
    !validId(actorId) ||
    !validId(candidateId) ||
    typeof excluded !== 'boolean'
  ) {
    throw new TypeError(
      'A valid actor, candidate and exclusion flag are required'
    );
  }

  const actionType = excluded
    ? 'candidate.exclude'
    : 'candidate.restore';

  return runAuditedAction(
    {
      actorId,
      action: actionType,
      target: `candidate:${candidateId}`
    },
    async client => {
      if (
        !signedAction ||
        signedAction.adminId !== actorId ||
        signedAction.candidateId !== candidateId ||
        signedAction.actionType !== actionType ||
        signedAction.newValue !== String(excluded)
      ) {
        throw new Error('Missing or mismatched administrator signature');
      }

      await storeSignedAction(client, signedAction);

      const updated = await client.query(
        `UPDATE candidates
         SET excluded = $1
         WHERE id = $2
         RETURNING id`,
        [excluded, candidateId]
      );

      if (updated.rowCount !== 1) {
        throw new Error('Candidate not found');
      }

      return { candidateId, excluded };
    }
  );
}

/**
 * Change a candidate's ballot order.
 */
async function setCandidateOrder(
  {
    actorId,
    candidateId,
    ballotOrder,
    signedAction
  },
  runAuditedAction = defaultRunner
) {
  if (
    !validId(actorId) ||
    !validId(candidateId) ||
    !validId(ballotOrder)
  ) {
    throw new TypeError(
      'A valid actor, candidate and ballot order are required'
    );
  }

  return runAuditedAction(
    {
      actorId,
      action: 'candidate.order',
      target: `candidate:${candidateId}`
    },
    async client => {
      if (
        !signedAction ||
        signedAction.adminId !== actorId ||
        signedAction.candidateId !== candidateId ||
        signedAction.actionType !== 'candidate.order' ||
        signedAction.newValue !== String(ballotOrder)
      ) {
        throw new Error('Missing or mismatched administrator signature');
      }

      await storeSignedAction(client, signedAction);

      const updated = await client.query(
        `UPDATE candidates
         SET ballot_order = $1
         WHERE id = $2
         RETURNING id`,
        [ballotOrder, candidateId]
      );

      if (updated.rowCount !== 1) {
        throw new Error('Candidate not found');
      }

      return { candidateId, ballotOrder };
    }
  );
}

module.exports = {
  setCandidateExclusion,
  setCandidateOrder
};
