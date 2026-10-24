// SR-05: Voter eligibility verification.
// Before a voter gets a ballot we check 3 things:
//   1. they exist and are actually a voter (not an admin etc.)
//   2. the election is open right now
//   3. they're enrolled for this election (and which division)
// If all good, we send back their division so they get the right ballot.

const db = require('../config/db');

async function checkEligibility(userId, electionId) {
  // make sure the ids are actual whole numbers, not random text
  if (!Number.isInteger(userId) || !Number.isInteger(electionId)) {
    return { eligible: false, reason: 'invalid_input' };
  }

  // 1. check the user exists and is a voter
  // ($1 is a parameter, so the input never gets mixed into the SQL = no SQL injection)
  const userResult = await db.query('SELECT role FROM users WHERE id = $1', [userId]);

  if (userResult.rowCount === 0) {
    return { eligible: false, reason: 'not_found' };
  }
  if (userResult.rows[0].role !== 'voter') {
    return { eligible: false, reason: 'not_a_voter' };
  }

  // 2. check the election exists and is open right now
  const electionResult = await db.query(
    'SELECT status, opens_at, closes_at FROM elections WHERE id = $1',
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
  const enrolResult = await db.query(
    'SELECT division_id FROM enrolments WHERE user_id = $1 AND election_id = $2',
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