// app.js
// This file sets up our Express app (the backend API).
// We keep it separate from server.js so our tests can use the app
// without actually starting the server.

const express = require('express');
const helmet = require('helmet');
const db = require('./config/db');

const app = express();

// helmet adds a bunch of security headers to every response.
// e.g. HSTS (forces HTTPS), nosniff, and stops our pages being put in iframes.
// This is part of SR-10 (encryption in transit).
app.use(helmet());

// Lets express read JSON from request bodies.
// We set a 10kb limit so someone can't send a huge request to slow the server down.
app.use(express.json({ limit: '10kb' }));

// Simple route to check the API is running.
// If you go to http://localhost:3000/api/health you should see {"status":"ok"}
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Checks the backend can actually talk to the database
app.get('/api/health/db', async (req, res, next) => {
  try {
    await db.query('SELECT 1');
    res.json({ database: 'ok' });
  } catch (err) {
    next(err);   // sends it to our error handler at the bottom
  }
});

// If someone asks for a route that doesn't exist, just send back 404.
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler - catches any errors from the routes above.
// We print the real error in our terminal, but only send a generic message
// to the user, so we don't leak details about our code (fail securely).
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;