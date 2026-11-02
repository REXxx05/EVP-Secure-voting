// SR-14: Digital signatures for election results.
// Uses Ed25519 and a dedicated tabulation-service signing key.

const crypto = require('crypto');
const path = require('path');

require('dotenv').config({
  path: path.resolve(__dirname, '../../../.env'),
  quiet: true
});

const RESULT_VERSION = 1;

// Load the private signing key from the environment.
// Never store the private key directly in source code.
function loadPrivateKey() {
  const encoded = process.env.RESULT_SIGNING_PRIVATE_KEY;

  if (!encoded) {
    throw new Error('RESULT_SIGNING_PRIVATE_KEY is missing');
  }

  let key;

  try {
    key = crypto.createPrivateKey(
      Buffer.from(encoded, 'base64').toString('utf8')
    );
  } catch {
    throw new Error('RESULT_SIGNING_PRIVATE_KEY is invalid');
  }

  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(
      'RESULT_SIGNING_PRIVATE_KEY must be an Ed25519 key'
    );
  }

  return key;
}

// Derive the corresponding public key.
function getPublicKey() {
  return crypto.createPublicKey(loadPrivateKey());
}

// Export the public key in PEM format.
// This can be distributed to trusted result-verification systems.
function getPublicKeyPem() {
  return getPublicKey().export({
    type: 'spki',
    format: 'pem'
  });
}

// Generate a short identifier for the signing key.
function keyIdOf(publicKey) {
  const der = publicKey.export({
    type: 'spki',
    format: 'der'
  });

  return crypto
    .createHash('sha256')
    .update(der)
    .digest('hex')
    .slice(0, 16);
}

// Validate the structure of election results.
function validateResults(results) {
  if (
    !results ||
    typeof results !== 'object' ||
    Array.isArray(results)
  ) {
    throw new Error('Invalid election results');
  }

  // Only these fields are permitted in the unsigned result payload.
  const allowedFields = ['electionId', 'results'];

  if (
    Object.keys(results).some(
      field => !allowedFields.includes(field)
    )
  ) {
    throw new Error('Unexpected election result field');
  }

  if (
    !Number.isSafeInteger(results.electionId) ||
    results.electionId < 1
  ) {
    throw new Error('Invalid election ID');
  }

  if (!Array.isArray(results.results)) {
    throw new Error(
      'Election results must contain a results array'
    );
  }

  const candidateIds = new Set();

  for (const entry of results.results) {
    if (
      !entry ||
      typeof entry !== 'object' ||
      Array.isArray(entry)
    ) {
      throw new Error('Invalid result entry');
    }

    const entryFields = ['candidateId', 'votes'];

    if (
      Object.keys(entry).some(
        field => !entryFields.includes(field)
      )
    ) {
      throw new Error('Unexpected candidate result field');
    }

    if (
      !Number.isSafeInteger(entry.candidateId) ||
      entry.candidateId < 1
    ) {
      throw new Error('Invalid candidate ID');
    }

    if (
      !Number.isSafeInteger(entry.votes) ||
      entry.votes < 0
    ) {
      throw new Error('Invalid vote count');
    }

    if (candidateIds.has(entry.candidateId)) {
      throw new Error('Duplicate candidate ID');
    }

    candidateIds.add(entry.candidateId);
  }
}

// Convert results into a consistent representation.
// Sorting ensures result ordering does not affect the signature.
function canonicalResults(results) {
  validateResults(results);

  const sortedResults = [...results.results]
    .sort((a, b) => a.candidateId - b.candidateId)
    .map(entry => ({
      candidateId: entry.candidateId,
      votes: entry.votes
    }));

  return JSON.stringify({
    domain: 'evp-election-results',
    version: RESULT_VERSION,
    electionId: results.electionId,
    results: sortedResults
  });
}

// Digitally sign election results.
function signResults(results) {
  const privateKey = loadPrivateKey();

  const publicKey = crypto.createPublicKey(privateKey);

  const payload = canonicalResults(results);

  const signature = crypto.sign(
    null,
    Buffer.from(payload, 'utf8'),
    privateKey
  );

  return {
    version: RESULT_VERSION,
    electionId: results.electionId,
    results: results.results.map(entry => ({
      candidateId: entry.candidateId,
      votes: entry.votes
    })),
    keyId: keyIdOf(publicKey),
    signature: signature.toString('base64')
  };
}

// Verify election results using a trusted public key.
// Invalid or altered packages are rejected.
function verifyResultsSignature(signedResults, trustedPublicKey) {
  try {
    if (
      !signedResults ||
      typeof signedResults !== 'object' ||
      Array.isArray(signedResults) ||
      signedResults.version !== RESULT_VERSION ||
      typeof signedResults.signature !== 'string' ||
      typeof signedResults.keyId !== 'string'
    ) {
      return false;
    }

    // Reject fields that are not covered by the signature.
    const allowedSignedFields = [
      'version',
      'electionId',
      'results',
      'keyId',
      'signature'
    ];

    if (
      Object.keys(signedResults).some(
        field => !allowedSignedFields.includes(field)
      )
    ) {
      return false;
    }

    // The public key must come from a trusted source.
    const publicKey =
      typeof trustedPublicKey === 'string'
        ? crypto.createPublicKey(trustedPublicKey)
        : trustedPublicKey;

    if (
      !publicKey ||
      publicKey.asymmetricKeyType !== 'ed25519'
    ) {
      return false;
    }

    // Confirm that the expected public key matches the key identifier.
    if (keyIdOf(publicKey) !== signedResults.keyId) {
      return false;
    }

    // Validate only the signed result payload.
    const payload = canonicalResults({
      electionId: signedResults.electionId,
      results: signedResults.results
    });

    return crypto.verify(
      null,
      Buffer.from(payload, 'utf8'),
      publicKey,
      Buffer.from(signedResults.signature, 'base64')
    );

  } catch {
    return false;
  }
}

module.exports = {
  RESULT_VERSION,
  signResults,
  verifyResultsSignature,
  getPublicKey,
  getPublicKeyPem,
  keyIdOf
};