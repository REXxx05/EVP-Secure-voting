// SR-03: Role-based access control.
// Runs AFTER requireAuth. Only the listed roles may continue; everyone else
// gets 403 and the attempt is written to the audit log.

const db = require('../config/db');

// Turns the request into a safe audit "target" such as POST:/api/admin/candidates/3/exclusion.
// Only letters, digits and _ . : / - are kept, as the audit log expects.
function auditTarget(req) {
  const raw = `${req.method}:${req.baseUrl || ''}${req.path || ''}`;
  return raw.replace(/[^A-Za-z0-9_.:/-]/g, '_').slice(0, 200);
}

// Records the denied attempt. If the log write fails, access is still denied.
async function logDenial(req) {
  try {
    await db.query(
      `INSERT INTO audit_log (actor_id, action, target, outcome, detail)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.id, 'access.denied', auditTarget(req), 'failure', 'role_not_permitted']
    );
  } catch (err) {
    // Fixed message only: never print user data to the console log
    console.error('Could not write access-denied audit row');
  }
}

// Usage: router.post('/x', requireAuth, requireRole('admin'), handler)
function requireRole(...allowedRoles) {
  return async function (req, res, next) {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Not logged in' });
      }

      if (!allowedRoles.includes(req.user.role)) {
        await logDenial(req);
        return res.status(403).json({ error: 'You do not have permission to do this' });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = requireRole;