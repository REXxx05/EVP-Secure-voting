// SR-03: Role-based access control.
// SR-17: Privacy-preserving logging for voter access-denied events.

const db = require('../config/db');
const { pseudonymiseVoter } = require('../security/voterPseudonym');

// Create a safe audit target for privileged-user events.
function auditTarget(req) {
  const raw = `${req.method}:${req.baseUrl || ''}${req.path || ''}`;

  return raw
    .replace(/[^A-Za-z0-9_.:/-]/g, '_')
    .slice(0, 200);
}

// Record access-denied events without exposing voter identifiers.
async function logDenial(req) {
  try {
    if (req.user.role === 'voter') {
      const pseudonym = pseudonymiseVoter(req.user.id);

      await db.query(
        `INSERT INTO voter_privacy_log
         (voter_pseudonym, event_type, reason)
         VALUES ($1, $2, $3)`,
        [
          pseudonym,
          'access.denied',
          'role_not_permitted'
        ]
      );

      return;
    }

    // Administrator and auditor events use the existing audit log.
    await db.query(
      `INSERT INTO audit_log
       (actor_id, action, target, outcome, detail)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        'access.denied',
        auditTarget(req),
        'failure',
        'role_not_permitted'
      ]
    );

  } catch (error) {
    // Avoid printing exception objects or sensitive user information.
    console.error('Could not write access-denied audit row');
  }
}

// IMPORTANT:
// requireRole('admin') must RETURN an Express middleware function.
function requireRole(...allowedRoles) {
  return async function (req, res, next) {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Not logged in'
        });
      }

      if (!allowedRoles.includes(req.user.role)) {
        await logDenial(req);

        return res.status(403).json({
          error: 'You do not have permission to do this'
        });
      }

      next();

    } catch (error) {
      next(error);
    }
  };
}

// Export the middleware factory, not the result of calling it.
module.exports = requireRole;