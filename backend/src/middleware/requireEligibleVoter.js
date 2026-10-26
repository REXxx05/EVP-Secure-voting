// SR-05: middleware that runs BEFORE the ballot and vote routes.
// It stops anyone who isn't allowed to vote in this election.
//
// It needs Dhanush's login middleware (SR-04) to run first,
// which puts the logged in user on the request as req.user = { id, role }.
// We agreed on that as a team, so this will work once login is plugged in.

const { checkEligibility } = require('../services/eligibilityService');

// simple messages to show the voter for each reason
// (we don't show any internal details)
const messages = {
  not_found: 'We could not find this election or your account.',
  not_a_voter: 'Only voters can vote in an election.',
  election_not_open: 'This election is not open for voting right now.',
  not_enrolled: 'You are not enrolled to vote in this election.',
  invalid_input: 'Invalid request.'
};

async function requireEligibleVoter(req, res, next) {
  try {
    // if there's no user, they haven't logged in
    if (!req.user) {
      return res.status(401).json({ error: 'Please log in first.' });
    }

    // the election id comes from the url, e.g. /api/elections/1/vote
    const electionId = Number(req.params.electionId);
    const userId = Number(req.user.id);

    const result = await checkEligibility(userId, electionId);

    if (!result.eligible) {
      // log that someone failed the check, but NOT who it was,
      // so logs can't be used to identify voters (SR-17)
      // TODO: switch this to the team audit log once SR-15 is done
      console.warn('Eligibility check failed: ' + result.reason + ' (election ' + electionId + ')');

      return res.status(403).json({ error: messages[result.reason] });
    }

    // they passed, so save the election and division for the next step (SR-06).
    // SR-06 should use this division and never one sent by the browser
    req.eligibility = {
      electionId: result.electionId,
      divisionId: result.divisionId
    };

    next();

  } catch (err) {
    // send any error to our error handler (it doesn't leak details)
    next(err);
  }
}

module.exports = requireEligibleVoter;