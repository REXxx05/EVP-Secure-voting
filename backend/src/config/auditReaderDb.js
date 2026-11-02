// SR-16: Dedicated database connection for reading audit information.
// Never use the normal application database account for these queries.

const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({
  path: path.resolve(__dirname, '../../../.env')
});

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'evp',
  user: process.env.AUDIT_READER_DB_USER,
  password: process.env.AUDIT_READER_DB_PASSWORD,
  max: 5
});

module.exports = pool;