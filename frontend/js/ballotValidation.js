// SR-07: client-side ballot validation.
// This only gives the voter instant feedback. It is NOT a security control:
// the server re-validates every ballot (backend/src/services/ballotValidator.js).
// Works in the browser (window.BallotValidation) and in Node/Jest (require).

(function (root) {
  'use strict';

  var SENATE_MIN_PREFERENCES = 6;
  var MAX_RANKING_LENGTH = 100;

  function isPositiveInt(value) {
    return typeof value === 'number' && Number.isInteger(value) && value > 0;
  }

  // Returns a problem message, or null if the ranking list looks fine
  function checkList(ranking, label) {
    if (!Array.isArray(ranking)) return label + ': the ballot must be a list of candidates';
    if (ranking.length > MAX_RANKING_LENGTH) return label + ': too many preferences';
    if (!ranking.every(isPositiveInt)) return label + ': contains an invalid candidate';
    if (new Set(ranking).size !== ranking.length) return label + ': a candidate is ranked twice';
    return null;
  }

  // ballots: { house: { ranking: [ids] }, senate: { ranking: [ids] } }
  // shown:   { houseCandidateIds: [ids on screen], senateCandidateIds: [ids on screen] }
  // Returns { valid: boolean, errors: [messages] }
  function validateBallots(ballots, shown) {
    var errors = [];
    var house = ballots && ballots.house && ballots.house.ranking;
    var senate = ballots && ballots.senate && ballots.senate.ranking;
    var houseIds = (shown && shown.houseCandidateIds) || [];
    var senateIds = (shown && shown.senateCandidateIds) || [];

    var houseProblem = checkList(house, 'House');
    if (houseProblem) {
      errors.push(houseProblem);
    } else {
      if (house.length !== houseIds.length) {
        errors.push('House: number every candidate on the ballot');
      } else if (!house.every(function (id) { return houseIds.indexOf(id) !== -1; })) {
        errors.push('House: contains a candidate who is not on this ballot');
      }
    }

    var senateProblem = checkList(senate, 'Senate');
    if (senateProblem) {
      errors.push(senateProblem);
    } else {
      if (senate.length < SENATE_MIN_PREFERENCES) {
        errors.push('Senate: number at least ' + SENATE_MIN_PREFERENCES + ' candidates');
      }
      if (!senate.every(function (id) { return senateIds.indexOf(id) !== -1; })) {
        errors.push('Senate: contains a candidate who is not on this ballot');
      }
    }

    return { valid: errors.length === 0, errors: errors };
  }

  var api = {
    SENATE_MIN_PREFERENCES: SENATE_MIN_PREFERENCES,
    MAX_RANKING_LENGTH: MAX_RANKING_LENGTH,
    validateBallots: validateBallots,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.BallotValidation = api;
  }
})(typeof window !== 'undefined' ? window : this);