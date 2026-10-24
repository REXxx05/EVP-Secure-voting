// This is the file that actually starts the backend.
// Run it with: npm run dev

const path = require('path');
const https = require('https');

// Load our settings (port, database details, secret keys, cert paths) from .env.
// The .env file is in the main project folder, two levels up from here.
require('dotenv').config({ path: path.resolve(__dirname, '../../.env'), quiet: true });

const app = require('./app');
const { getTlsOptions } = require('./config/tls');

// Use the port from .env, or 3000 if it's not set
const PORT = process.env.PORT || 3000;

// SR-10: start an HTTPS server instead of plain HTTP.
// We don't run any plain HTTP server at all, so unencrypted
// connections just get refused.
https.createServer(getTlsOptions(), app).listen(PORT, () => {
  console.log(`EVP API running on https://localhost:${PORT}`);
});