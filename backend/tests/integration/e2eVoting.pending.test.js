// SR-06 end-to-end tests that need the REAL SR-01/SR-04 login and session code.
// SR-04 (origin/dhanush/sr-01-03-04-07-19) is not merged into main, and there is no
// real login route, authentication middleware or CSRF check yet, so these stay
// explicitly pending. They are not faked: no test double stands in for authentication.
// When SR-01/SR-04 and SR-07 are merged, implement these against the mounted
// createBallotsRouter with the real collaborators:
//   authenticateVoter  <- SR-04 session lookup (populates req.user / req.session)
//   verifyCsrf         <- SR-04 CSRF check
//   validateBallots    <- SR-07 House/Senate validator
//   invalidateSession  <- SR-04 session invalidation using the transaction client
describe('SR-06 end-to-end with real authentication (pending SR-01/SR-04/SR-07 merge)', () => {
  test.todo('real login -> real session -> POST /api/elections/:id/ballots with House and Senate -> 201 with a receipt');
  test.todo('the session is invalidated by the same transaction that commits the ballots');
  test.todo('a second submission by the same authenticated voter is rejected (409 ALREADY_VOTED)');
  test.todo('a second submission with a freshly renewed session is still rejected by the participation key');
  test.todo('an unauthenticated or expired-session submission is rejected before any database write');
});
