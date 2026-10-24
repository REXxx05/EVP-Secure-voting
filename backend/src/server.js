// server.js
// This is the file that actually starts the backend.
// Run it with: npm run dev

const path = require('path');

// Load our settings (port, database details, secret keys) from the .env file.
// It's in .gitignore so our secrets never get pushed to GitHub.
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const app = require('./app');

// Use the port from .env, or 3000 if it's not set
const PORT = process.env.PORT || 3000;

// Start listening for requests
app.listen(PORT, () => {
  console.log(`EVP API listening on port ${PORT}`);
});