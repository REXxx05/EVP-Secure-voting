// Checks the HSTS header (SR-10) is sent with the right settings,
// so browsers only use HTTPS for our site.

const request = require('supertest');
const app = require('../../src/app');
const db = require('../../src/config/db');

describe('SR-10 HSTS header', () => {

  it('tells browsers to use HTTPS only for 1 year, including subdomains', async () => {
    const res = await request(app).get('/api/health');
    const hsts = res.headers['strict-transport-security'];

    expect(hsts).toContain('max-age=31536000');
    expect(hsts).toContain('includeSubDomains');
  });

});

// app.js opens database connections, so close them when we're done
afterAll(async () => {
  await db.pool.end();
});