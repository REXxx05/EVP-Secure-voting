// db.test.js
// Checks the backend can connect to the database as the app user.
// The Docker database needs to be running for this test to pass.

const request = require('supertest');
const app = require('../../src/app');
const db = require('../../src/config/db');

describe('GET /api/health/db', () => {

  it('connects to the database', async () => {
    const res = await request(app).get('/api/health/db');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ database: 'ok' });
  });

});

// Close the database connections after the tests,
// otherwise Jest keeps waiting and never finishes
afterAll(async () => {
  await db.pool.end();
});