// SR-05: Verify that the authenticated user is eligible to vote.
// SR-17: Record eligibility denials using privacy-preserving logs.

const db = require('../config/db');
const { checkEligibility } = require('../services/eligibilityService');
const { pseudonymiseVoter } = require('../security/voterPseudonym');

const messages = {
  not_found: 'We could not find this election or your account.',
  not_a_voter: 'Only voters can vote in an election.',
  election_not_open: 'This election is not open for voting right now.',
  not_enrolled: 'You are not enrolled to vote in this election.',
  invalid_input: 'Invalid request.'
};

// Record eligibility denials without storing direct voter identifiers.
async function logEligibilityDenial(userId, role, reason) {
  if (role !== 'voter') {
    return;
  }

  try {
    const pseudonym = pseudonymiseVoter(userId);

    const safeReason = Object.prototype.hasOwnProperty.call(
      messages,
      reason
    )
      ? reason
      : 'invalid_input';

    await db.query(
      `INSERT INTO voter_privacy_log
       (voter_pseudonym, event_type, reason)
       VALUES ($1, $2, $3)`,
      [
        pseudonym,
        'eligibility.denied',
        safeReason
      ]
    );

  } catch (error) {
    // Do not expose voter information or database errors.
    console.error('Could not write eligibility-denied privacy log');
  }
}

async function requireEligibleVoter(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Please log in first.'
      });
    }

    const electionId = Number(req.params.electionId);
    const userId = Number(req.user.id);

    const result = await checkEligibility(userId, electionId);

    if (!result.eligible) {
      await logEligibilityDenial(
        userId,
        req.user.role,
        result.reason
      );

      const message = messages[result.reason] || messages.invalid_input;

      return res.status(403).json({
        error: message
      });
    }

    req.eligibility = {
      electionId: result.electionId,
      divisionId: result.divisionId
    };

    next();

  } catch (error) {
    next(error);
  }
}

module.exports = requireEligibleVoter;