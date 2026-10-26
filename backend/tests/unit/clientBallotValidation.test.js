// SR-07: unit tests for the browser-side ballot validation module.

const { validateBallots, SENATE_MIN_PREFERENCES } = require('../../../frontend/js/ballotValidation');

const shown = {
  houseCandidateIds: [1, 2, 3],
  senateCandidateIds: [1, 2, 3, 4, 5, 6, 7],
};

const goodHouse = { ranking: [3, 1, 2] };
const goodSenate = { ranking: [7, 1, 2, 3, 4, 5] };

describe('client-side ballot validation (SR-07)', () => {
  test('accepts a complete, correct ballot', () => {
    const result = validateBallots({ house: goodHouse, senate: goodSenate }, shown);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('asks the voter to number every House candidate', () => {
    const result = validateBallots({ house: { ranking: [1, 2] }, senate: goodSenate }, shown);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toMatch(/House/);
  });

  test('requires the minimum number of Senate preferences', () => {
    const result = validateBallots({ house: goodHouse, senate: { ranking: [1, 2, 3] } }, shown);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain(String(SENATE_MIN_PREFERENCES));
  });

  test('flags a candidate ranked twice', () => {
    const result = validateBallots({ house: { ranking: [1, 1, 2] }, senate: goodSenate }, shown);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/twice/);
  });

  test('flags a candidate who is not on the ballot', () => {
    const result = validateBallots({ house: { ranking: [1, 2, 99] }, senate: goodSenate }, shown);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/not on this ballot/);
  });

  test('flags text, decimals and negative numbers', () => {
    for (const ranking of [['a', 2, 3], [1.5, 2, 3], [-1, 2, 3]]) {
      const result = validateBallots({ house: { ranking }, senate: goodSenate }, shown);
      expect(result.valid).toBe(false);
    }
  });

  test('flags an oversized ballot', () => {
    const huge = Array.from({ length: 101 }, (_, i) => i + 1);
    const result = validateBallots({ house: goodHouse, senate: { ranking: huge } }, shown);
    expect(result.valid).toBe(false);
  });

  test('copes with missing or malformed ballots without throwing', () => {
    expect(validateBallots(undefined, shown).valid).toBe(false);
    expect(validateBallots({}, shown).valid).toBe(false);
    expect(validateBallots({ house: 'x', senate: null }, shown).valid).toBe(false);
  });

  test('reports problems in both chambers at once', () => {
    const result = validateBallots({ house: { ranking: [] }, senate: { ranking: [] } }, shown);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBe(2);
  });
});
