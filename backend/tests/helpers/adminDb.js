// Connects to the database as the ADMIN user.
// ONLY used in tests, so we can add fake test data and delete it after.
// (the normal app user can't delete anything, which is on purpose)

const path = require('path');
const { Pool } = require('pg');

require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

const adminDb = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_ADMIN_USER,
  password: process.env.DB_ADMIN_PASSWORD
});

module.exports = adminDb;