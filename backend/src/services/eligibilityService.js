// eligibilityService.js
// SR-05: Voter eligibility verification.
// Before a voter gets a ballot we check 3 things:
//   1. they exist and are actually a voter (not an admin etc.)
//   2. the election is open right now
//   3. they're enrolled for this election (and which division)
// If all good, we send back their division so they get the right ballot.
//
// Options (used by SR-06 when saving a vote):
//   client - the connection from SR-06's transaction, so this check
//            happens inside the same transaction as saving the vote
//   lock   - if true, we lock the election and enrolment rows (FOR SHARE)
//            until the transaction finishes. This means an admin can't close
//            the election or change the enrolment halfway through a vote.
//            FOR SHARE still lets other voters vote at the same time.

const db = require('../config/db');

async function checkEligibility(userId, electionId, options = {}) {
  // use SR-06's transaction if we were given one, otherwise the normal pool
  const runner = options.client || db;

  // locking only makes sense inside a transaction, so don't allow it without one
  if (options.lock && !options.client) {
    throw new Error('lock needs a transaction client');
  }

  // this gets added to the end of the queries when we want to lock rows.
  // it's safe to join it into the SQL because it's our own fixed text
  // (either ' FOR SHARE' or nothing), never anything the user typed
  const lockText = options.lock ? ' FOR SHARE' : '';

  // make sure the ids are actual whole numbers, not random text
  if (!Number.isInteger(userId) || !Number.isInteger(electionId)) {
    return { eligible: false, reason: 'invalid_input' };
  }

  // 1. check the user exists and is a voter
  // ($1 is a parameter, so the input never gets mixed into the SQL = no SQL injection)
  const userResult = await runner.query('SELECT role FROM users WHERE id = $1', [userId]);

  if (userResult.rowCount === 0) {
    return { eligible: false, reason: 'not_found' };
  }
  if (userResult.rows[0].role !== 'voter') {
    return { eligible: false, reason: 'not_a_voter' };
  }

  // 2. check the election exists and is open right now
  // (we always lock the election BEFORE the enrolment, same order every time,
  //  so two transactions can't end up waiting on each other forever)
  const electionResult = await runner.query(
    'SELECT status, opens_at, closes_at FROM elections WHERE id = $1' + lockText,
    [electionId]
  );

  if (electionResult.rowCount === 0) {
    return { eligible: false, reason: 'not_found' };
  }

  const election = electionResult.rows[0];
  const now = new Date();

  // it has to be marked open AND we have to be inside the voting dates
  const isOpen =
    election.status === 'open' &&
    (!election.opens_at || election.opens_at <= now) &&
    (!election.closes_at || election.closes_at > now);

  if (!isOpen) {
    return { eligible: false, reason: 'election_not_open' };
  }

  // 3. check they're enrolled for this election, and get their division
  const enrolResult = await runner.query(
    'SELECT division_id FROM enrolments WHERE user_id = $1 AND election_id = $2' + lockText,
    [userId, electionId]
  );

  if (enrolResult.rowCount === 0) {
    return { eligible: false, reason: 'not_enrolled' };
  }

  // all good!
  // the division comes from the enrolment table, NOT from the browser,
  // so a voter can't just pick a different division
  return {
    eligible: true,
    electionId: electionId,
    divisionId: enrolResult.rows[0].division_id
  };
}

module.exports = { checkEligibility };