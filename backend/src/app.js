// app.js
// This file sets up our Express app (the backend API).
// We keep it separate from server.js so our tests can use the app
// without actually starting the server.

const express = require('express');
const helmet = require('helmet');
const db = require('./config/db');
const path = require('path');

const authRoutes = require('./routes/auth');
const mfaRoutes = require('./routes/mfa');    // SR-02
const { createBulletinBoardRouter } = require('./routes/bulletinBoard');
const { apiLimiter } = require('./middleware/rateLimiters');
const adminRoutes = require('./routes/admin');

// SR-16: Auditor-only access to audit logs and integrity alerts.
const auditorRoutes = require('./routes/auditor');

const app = express();

// Helmet adds security headers to every response.
// HSTS (SR-10) tells the browser to use HTTPS for the site.
app.use(helmet({
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true
  }
}));

// Allow Express to read JSON request bodies.
// Limit request size to 10 KB to reduce abuse.
app.use(express.json({ limit: '10kb' }));

// Serve frontend files (HTML, CSS, JS).
app.use(express.static(path.join(__dirname, '../../frontend')));

// SR-19: Apply rate limiting to API requests.
app.use('/api', apiLimiter);

// Check whether the API is running.
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Check whether the database connection is working.
app.get('/api/health/db', async (req, res, next) => {
  try {
    await db.query('SELECT 1');

    res.json({
      database: 'ok'
    });

  } catch (err) {
    next(err);
  }
});

// SR-01, SR-04: Authentication and session handling.
app.use('/api/auth', authRoutes);

// SR-03: Administrator routes with role-based access control.
app.use('/api/admin', adminRoutes);

// SR-16: Auditor-only access to audit logs and integrity alerts.
// Requires a valid session, completed MFA and the auditor role.
app.use('/api/auditor', auditorRoutes);

// SR-02: Administrator multi-factor authentication.
app.use('/api/mfa', mfaRoutes);

// SR-12: Public bulletin board for receipt verification.
app.use(createBulletinBoardRouter({ db }));

// Return 404 for unknown routes.
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found'
  });
});

// ============================================================
// SR-17: Privacy-Safe Application Error Handling
// ============================================================
//
// Security requirement:
// - Do not expose voter identifiers in application logs.
// - Do not log IP addresses.
// - Do not log ballot contents or voting preferences.
// - Do not log request bodies or session information.
// - Do not print complete error objects that may contain
//   sensitive information.
//
// The application records only a fixed error message.
// Detailed exception information is not printed.
//
// This reduces the risk of exposing voter information
// through application error logging.
// ============================================================

app.use((err, req, res, next) => {

  // Fixed message without sensitive information.
  console.error('Internal application error');

  // Return a generic error response.
  res.status(500).json({
    error: 'Internal server error'
  });

});

module.exports = app;