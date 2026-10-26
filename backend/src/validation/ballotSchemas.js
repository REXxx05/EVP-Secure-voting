// SR-07: server-side input schemas (zod).
// These check the SHAPE of data. Rules that need the database
// (does this candidate exist in the voter's division?) live in
// services/ballotValidator.js.

const { z } = require('zod');

// Easy-to-change rules
const MAX_RANKING_LENGTH = 100;      // nobody needs more than this many preferences
const HOUSE_MIN_PREFERENCES = 1;     // the exact count is checked against the database
const SENATE_MIN_PREFERENCES = 6;

const candidateId = z.number().int().positive();

function rankingSchema(minLength) {
  return z
    .strictObject({
      ranking: z.array(candidateId).min(minLength).max(MAX_RANKING_LENGTH),
    })
    .refine((ballot) => new Set(ballot.ranking).size === ballot.ranking.length, {
      message: 'A candidate cannot be ranked twice',
    });
}

const houseSchema = rankingSchema(HOUSE_MIN_PREFERENCES);
const senateSchema = rankingSchema(SENATE_MIN_PREFERENCES);

// strictObject rejects any extra fields
const ballotsSchema = z.strictObject({
  house: houseSchema,
  senate: senateSchema,
});

// Login input (SR-01): only these two fields, as text, with sane lengths
const loginSchema = z.strictObject({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(200),
});

module.exports = {
  MAX_RANKING_LENGTH,
  SENATE_MIN_PREFERENCES,
  houseSchema,
  senateSchema,
  ballotsSchema,
  loginSchema,
};