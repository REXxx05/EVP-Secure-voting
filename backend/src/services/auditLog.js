// SR-15: audit logging for privileged (administrator) actions.
//
// runAuditedAction runs a privileged action and records who did what, to what,
// when (UTC) and whether it worked:
//   - success: the audit row is written in the SAME database transaction as the
//     action. If the row cannot be written, the action is rolled back (blocked).
//   - failure (the action threw, or the actor is not allowed): everything the
//     action did is rolled back, then a failure row is written. If even that row
//     cannot be written the caller gets an AUDIT_WRITE_FAILED error.
//
// So a privileged action cannot take effect without its audit record. The work
// function must do its database changes through the client it is given; changes
// made any other way (other connections, files) are outside this guarantee.
//
// `actorId` must come from the authenticated session (SR-02/SR-03), never from
// the request body. `target` must not contain voter identifiers (SR-17).

const defaultDb = require('../config/db');

class AuditError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'AuditError';
    this.code = code;
  }
}

const ACTION_PATTERN = /^[a-z][a-z0-9_.:-]{0,99}$/;
const TARGET_PATTERN = /^[A-Za-z0-9_.:/-]{1,200}$/;
const INSERT_AUDIT = `INSERT INTO audit_log (actor_id, action, target, outcome, detail)
                      VALUES ($1, $2, $3, $4, $5)`;   // no RETURNING: the app may insert but not read audit_log

function createAuditedRunner({ pool = defaultDb.pool } = {}) {
  async function recordFailure(actorId, action, target, detail) {
    try {
      await pool.query(INSERT_AUDIT, [actorId, action, target, 'failure', detail]);
    } catch (cause) {
      throw new AuditError('AUDIT_WRITE_FAILED', 'Failed action could not be audit-logged', { cause });
    }
  }

  return async function runAuditedAction(
    { actorId, action, target, allowedRoles = ['admin'] } = {}, work
  ) {
    if (!Number.isSafeInteger(actorId) || actorId < 1 ||
        typeof action !== 'string' || !ACTION_PATTERN.test(action) ||
        typeof target !== 'string' || !TARGET_PATTERN.test(target) ||
        typeof work !== 'function') {
      throw new AuditError('INVALID_AUDIT_INPUT', 'Actor, action, target and work are required');
    }

    const client = await pool.connect();
    let inTransaction = false;
    let discardClient = false;
    let result;
    let failure;
    let failureDetail;
    try {
      await client.query('BEGIN');
      inTransaction = true;

      const actor = await client.query('SELECT role FROM users WHERE id = $1', [actorId]);
      if (actor.rowCount !== 1) {
        throw new AuditError('INVALID_ACTOR', 'Unknown actor');
      }
      if (!allowedRoles.includes(actor.rows[0].role)) {
        failure = new AuditError('FORBIDDEN', 'Actor is not permitted to perform this action');
        failureDetail = 'not_authorised';
      } else {
        try {
          result = await work(client);
        } catch (error) {
          failure = error;
          failureDetail = 'action_error';
        }
      }

      if (!failure) {
        // The success record commits (or fails) together with the action itself.
        await client.query(INSERT_AUDIT, [actorId, action, target, 'success', null]);
        await client.query('COMMIT');
        inTransaction = false;
        return { result, audited: true };
      }
    } catch (error) {
      if (error instanceof AuditError && error.code === 'INVALID_ACTOR') {
        failure = error; failureDetail = null;
      } else {
        // The audit row (or the commit) failed: the action must not take effect.
        failure = new AuditError('AUDIT_WRITE_FAILED', 'Action blocked: audit record could not be written',
          { cause: error });
        failureDetail = null;
        if (!inTransaction) discardClient = true;
      }
    } finally {
      if (inTransaction) {
        try { await client.query('ROLLBACK'); } catch (rollbackError) { discardClient = true; }
      }
      client.release(discardClient);
    }

    // Reached only on failure; the action's changes are already rolled back.
    if (failureDetail) {
      await recordFailure(actorId, action, target, failureDetail);
    }
    throw failure;
  };
}

module.exports = { createAuditedRunner, AuditError };
