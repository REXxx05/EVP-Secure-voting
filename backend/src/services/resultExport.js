// SR-14: Verify digitally signed election results before export.
//
// Security requirements:
// 1. The election must pass SR-13 reconciliation.
// 2. The signed results must belong to the requested election.
// 3. The digital signature must be valid.
// 4. The verification key must come from a trusted source.
// 5. Invalid or altered results must never be exported.
//
// This module does not calculate election results.
// The authorised tally service must produce those results.

const {
  verifyResultsSignature
} = require('../security/resultSigning');

const {
  reconcileElection
} = require('./ballotReconciliation');

class ResultExportError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ResultExportError';
    this.code = code;
  }
}

/**
 * Verify the digital signature of an election-results package.
 *
 * The trusted public key must be supplied independently of the
 * signed package.
 *
 * @param {object} signedResults
 * @param {string|object} trustedPublicKey
 * @returns {object}
 */
function verifyResultsForExport(signedResults, trustedPublicKey) {
  if (!trustedPublicKey) {
    throw new ResultExportError(
      'Trusted results verification key is unavailable',
      'TRUSTED_KEY_MISSING'
    );
  }

  if (!verifyResultsSignature(signedResults, trustedPublicKey)) {
    throw new ResultExportError(
      'Election results signature verification failed',
      'INVALID_RESULT_SIGNATURE'
    );
  }

  return signedResults;
}

/**
 * Perform all security checks required before exporting results.
 *
 * This function is intended to be called by an authorised export
 * workflow after the tally service has produced signed results.
 *
 * @param {number} electionId
 * @param {object} signedResults
 * @param {string|object} trustedPublicKey
 * @param {object} options
 * @returns {Promise<object>}
 */
async function prepareResultsForExport(
  electionId,
  signedResults,
  trustedPublicKey,
  options = {}
) {
  // Validate the requested election.
  if (
    !Number.isSafeInteger(electionId) ||
    electionId < 1
  ) {
    throw new ResultExportError(
      'A valid election ID is required',
      'INVALID_ELECTION'
    );
  }

  // Validate the signed package.
  if (
    !signedResults ||
    typeof signedResults !== 'object' ||
    Array.isArray(signedResults)
  ) {
    throw new ResultExportError(
      'A signed election-results package is required',
      'INVALID_RESULT_PACKAGE'
    );
  }

  // Prevent results from one election being exported as another.
  if (signedResults.electionId !== electionId) {
    throw new ResultExportError(
      'Signed results do not belong to the requested election',
      'ELECTION_MISMATCH'
    );
  }

  // Verify the signature before performing further work.
  verifyResultsForExport(signedResults, trustedPublicKey);

  // The real SR-13 reconciliation function is used by default.
  // An alternative can be injected for isolated unit tests.
  const reconcile =
    options.reconcile || reconcileElection;

  // Reconciliation checks ballot counts, hashes, receipts
  // and verified tally inputs.
  //
  // IMPORTANT: The reconciliation result may contain decrypted
  // ballots. Never return those ballots from an export function.
  const reconciliation = await reconcile(electionId);

  if (!reconciliation || reconciliation.ok !== true) {
    throw new ResultExportError(
      'Election reconciliation failed; results export blocked',
      'RECONCILIATION_FAILED'
    );
  }

  // Return only the verified signed package.
  // Do not expose decrypted ballots or voter information.
  return signedResults;
}

module.exports = {
  verifyResultsForExport,
  prepareResultsForExport,
  ResultExportError
};