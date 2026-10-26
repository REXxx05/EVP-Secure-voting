// SR-07: server-side ballot validation.
// Called by the ballot submission service inside its transaction:
//   validateBallots({ client, electionId, divisionId, house, senate })
// Returns true ONLY if both ballots are valid. Anything else returns false
// (or throws, which the submission service also treats as a rejection).

const { ballotsSchema } = require('../validation/ballotSchemas');

function isPositiveInt(value) {
  return Number.isSafeInteger(value) && value > 0;
}

async function validateBallots({ client, electionId, divisionId, house, senate } = {}) {
  // 1. Shape: strict objects, whole-number ids, no duplicates, length limits
  const parsed = ballotsSchema.safeParse({ house, senate });
  if (!parsed.success) return false;
  if (!client || !isPositiveInt(electionId) || !isPositiveInt(divisionId)) return false;

  const houseRanking = parsed.data.house.ranking;
  const senateRanking = parsed.data.senate.ranking;

  // 2. House: rank EVERY non-excluded candidate in the voter's own division, once each
  const houseResult = await client.query(
    `SELECT id FROM candidates
     WHERE election_id = $1 AND division_id = $2 AND excluded = FALSE`,
    [electionId, divisionId]
  );
  const houseAllowed = new Set(houseResult.rows.map((row) => row.id));
  const houseOk =
    houseRanking.length === houseAllowed.size &&
    houseRanking.every((id) => houseAllowed.has(id));
  if (!houseOk) return false;

  // 3. Senate: only non-excluded candidates from this election in the voter's state
  const senateResult = await client.query(
    `SELECT c.id
     FROM candidates c
     JOIN divisions d ON d.id = c.division_id
     WHERE c.election_id = $1
       AND c.excluded = FALSE
       AND d.state = (SELECT state FROM divisions WHERE id = $2)`,
    [electionId, divisionId]
  );
  const senateAllowed = new Set(senateResult.rows.map((row) => row.id));
  const senateOk = senateRanking.every((id) => senateAllowed.has(id));
  if (!senateOk) return false;

  return true;
}

module.exports = { validateBallots };