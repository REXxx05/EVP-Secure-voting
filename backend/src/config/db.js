// db.js
// Sets up the connection to our PostgreSQL database.
// Every other file that needs the database imports this one,
// so the connection settings live in one place.

const path = require('path');
const { Pool } = require('pg');

// Load the .env file (two folders up from here) so we have the DB details
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), quite: true });

// A "pool" keeps a few connections open and reuses them,
// which is faster than opening a new connection for every request.
// We log in as the LIMITED app user (DB_USER), never the admin.
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 10   // at most 10 connections at once
});

// Helper for running queries.
// IMPORTANT: always pass user input in "params", never glue it into the SQL text.
// e.g. query('SELECT * FROM users WHERE username = $1', [username])
// This stops SQL injection because the input is never treated as SQL.
function query(text, params) {
  return pool.query(text, params);
}

module.exports = { query, pool };