// SR-16: Auditor-only access to audit records and integrity alerts.

const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const requireMfa = require('../middleware/requireMfa');
const requireRole = require('../middleware/requireRole');
const auditReaderDb = require('../config/auditReaderDb');

const router = express.Router();

// All auditor endpoints require authentication, MFA and auditor role.
router.use(requireAuth);
router.use(requireMfa);
router.use(requireRole('auditor'));

// GET /api/auditor/logs
// Retrieve the latest 100 audit records.
router.get('/logs', async (req, res, next) => {
  try {
    const result = await auditReaderDb.query(
      `SELECT
         id,
         actor_id,
         action,
         target,
         outcome,
         detail,
         occurred_at,
         previous_hash,
         entry_hash
       FROM public.audit_log
       ORDER BY id DESC
       LIMIT 100`
    );

    return res.json({
      records: result.rows
    });
  } catch (error) {
    return next(error);
  }
});

// GET /api/auditor/integrity-alerts
// Retrieve the latest 100 integrity alerts.
router.get('/integrity-alerts', async (req, res, next) => {
  try {
    const result = await auditReaderDb.query(
      `SELECT
         id,
         detected_at,
         issue_count,
         checked_records,
         details
       FROM public.audit_integrity_alerts
       ORDER BY id DESC
       LIMIT 100`
    );

    return res.json({
      alerts: result.rows
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;