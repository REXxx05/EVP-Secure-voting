// SR-10: HTTPS settings (encryption in transit).
// Loads our certificate and only allows TLS 1.3 connections.

const fs = require('fs');
const path = require('path');

// Builds the options for Node's https server.
// Kept as a separate function so we can unit test it without real cert files.
function buildTlsOptions(cert, key) {
  return {
    cert: cert,
    key: key,
    minVersion: 'TLSv1.3'   // refuse TLS 1.2, 1.1, 1.0 and anything older
  };
}

// Reads the certificate and key files (paths come from .env)
function getTlsOptions() {
  // tls.js is in backend/src/config, so the project root is 3 folders up
  const projectRoot = path.resolve(__dirname, '../../..');
  const certPath = path.resolve(projectRoot, process.env.TLS_CERT_PATH || 'certs/cert.pem');
  const keyPath = path.resolve(projectRoot, process.env.TLS_KEY_PATH || 'certs/key.pem');

  // Fail securely: if there's no certificate, don't start at all.
  // We never fall back to plain HTTP, because that would send passwords
  // and ballots unencrypted.
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error('TLS certificate or key not found. Create them with mkcert (see README).');
  }

  return buildTlsOptions(fs.readFileSync(certPath), fs.readFileSync(keyPath));
}

module.exports = { buildTlsOptions, getTlsOptions };