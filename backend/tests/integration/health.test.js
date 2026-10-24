// health.test.js
// First test to check our basic setup works.
// supertest lets us send fake requests to the app without starting the server.

const request = require('supertest');
const app = require('../../src/app');

describe('GET /api/health', () => {

  // The health route should reply with status ok
  it('returns status ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  // Check helmet is actually adding the security headers (SR-10)
  it('sets security headers', async () => {
    const res = await request(app).get('/api/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['strict-transport-security']).toBeDefined();
  });

  // Unknown routes should give 404, not crash or leak info
  it('returns 404 for unknown routes', async () => {
    const res = await request(app).get('/api/does-not-exist');
    expect(res.status).toBe(404);
  });

});