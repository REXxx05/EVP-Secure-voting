// SR-08: saves a ballot with NO link to the voter.
//
// This function never even gets told who the voter is. It only gets the
// election, division, ballot type and the votes, so it can't save
// anything that identifies them.
//
// SR-06 calls this inside its transaction (so it takes the "client"
// from that transaction), once for the House ballot and once for the Senate.

const { encrypt, getCurrentKeyVersion } = require('../security/encryption');

async function saveBallotAnonymously(client, ballot) {
  const electionId = ballot.electionId;
  const divisionId = ballot.divisionId;
  const ballotType = ballot.ballotType;
  const ballotData = ballot.ballotData;

  // basic checks so we don't save rubbish
  if (!Number.isInteger(electionId) || !Number.isInteger(divisionId)) {
    throw new Error('Invalid election or division');
  }
  if (ballotType !== 'house' && ballotType !== 'senate') {
    throw new Error('Invalid ballot type');
  }
  if (!ballotData) {
    throw new Error('Ballot data is missing');
  }

  // turn the votes into text and encrypt them (SR-09),
  // so even someone reading the database can't see who people voted for
  const encryptedBallot = encrypt(JSON.stringify(ballotData));

  // save it. Notice there's no user id, and no timestamp.
  // The id is a random UUID made by the database, so the order
  // ballots were saved in can't be matched to when people logged in.
  const result = await client.query(
    `INSERT INTO ballots (election_id, division_id, ballot_type, ballot_data_enc, key_version)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id`,
    [electionId, divisionId, ballotType, encryptedBallot, getCurrentKeyVersion()]
  );

  // give back the ballot id so SR-11 can hash it and SR-12 can make the receipt
  return result.rows[0].id;
}

module.exports = { saveBallotAnonymously };