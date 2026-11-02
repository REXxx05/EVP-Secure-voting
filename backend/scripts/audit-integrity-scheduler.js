// SR-16: Run audit integrity verification every 15 minutes.
//
// This process must run separately from the web server.
// It uses the dedicated audit checker database credentials.

const { spawn } = require('child_process');
const path = require('path');

const INTERVAL_MS = 15 * 60 * 1000;

const checkerScript = path.join(__dirname, 'check-audit-integrity.js');

let running = false;

function runIntegrityCheck() {
  if (running) {
    console.warn('Previous audit integrity check is still running. Skipping.');
    return;
  }

  running = true;

  console.log(
    `[${new Date().toISOString()}] Starting scheduled audit integrity check`
  );

  const child = spawn(process.execPath, [checkerScript], {
    stdio: 'inherit',
    env: process.env
  });

  child.on('error', (error) => {
    console.error('Could not start audit integrity checker:', error.message);
  });

  child.on('close', (code) => {
    running = false;

    if (code !== 0) {
      console.error(
        `[${new Date().toISOString()}] Audit integrity check failed or detected tampering`
      );
    }
  });
}

// Run immediately when the scheduler starts.
runIntegrityCheck();

// Run every 15 minutes afterwards.
const timer = setInterval(runIntegrityCheck, INTERVAL_MS);

// Shut down cleanly when requested.
function shutdown() {
  console.log('Stopping audit integrity scheduler...');
  clearInterval(timer);
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

console.log('SR-16 audit integrity scheduler started (15-minute interval).');