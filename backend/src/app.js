// app.js
// This file sets up our Express app (the backend API).
// We keep it separate from server.js so our tests can use the app
// without actually starting the server.

const express = require('express');
const helmet = require('helmet');
const db = require('./config/db');
const path = require('path');
const { createBulletinBoardRouter } = require('./routes/bulletinBoard');

const app = express();

// helmet adds a bunch of security headers to every response.
// HSTS (SR-10) tells the browser to ONLY ever use HTTPS for our site
// for the next year, even if someone types http:// or clicks an http link.
app.use(helmet({
  hsts: {
    maxAge: 31536000,        // 1 year in seconds
    includeSubDomains: true
  }
}));

// Lets express read JSON from request bodies.
// We set a 10kb limit so someone can't send a huge request to slow the server down.
app.use(express.json({ limit: '10kb' }));

// Serve our frontend files (HTML, CSS, JS) from the frontend folder.
// So http://localhost:3000/ opens frontend/index.html
app.use(express.static(path.join(__dirname, '../../frontend')));

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

// SR-12: public bulletin board where voters check their receipts
app.use(createBulletinBoardRouter({ db }));

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