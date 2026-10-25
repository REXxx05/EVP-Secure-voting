// SR-19: end-to-end rate limiting against the real app.
// A small API limit is set BEFORE the app loads so a flood is quick to simulate.
process.env.RATE_LIMIT_API_MAX = '40';

const request = require('supertest');
const app = require('../../src/app');
const pool = require('../../src/config/db');

beforeAll(async () => {
  await pool.query(
    "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = 'voter1'"
  );
});

afterAll(async () => {
  await pool.pool.end();
});

describe('SR-19 rate limiting on the real app', () => {
  it('blocks one account after repeated failed logins, but other accounts still work', async () => {
    let lastStatus;
    for (let i = 0; i < 11; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'nobody', password: 'wrong-password' });
      lastStatus = res.status;
    }
    // The 11th failed attempt for the same account is blocked
    expect(lastStatus).toBe(429);

    // A different, legitimate account is unaffected
    const legit = await request(app)
      .post('/api/auth/login')
      .send({ username: 'voter1', password: 'Password123!' });
    expect(legit.status).toBe(200);
  });

  it('returns 429 during a flood and stays fast', async () => {
    const times = [];
    const flood = Array.from({ length: 100 }, async () => {
      const start = Date.now();
      const res = await request(app).get('/api/health');
      times.push(Date.now() - start);
      return res.status;
    });
    const statuses = await Promise.all(flood);

    const allowed = statuses.filter((s) => s === 200).length;
    const blocked = statuses.filter((s) => s === 429).length;
    expect(blocked).toBeGreaterThan(0);
    expect(allowed).toBeLessThanOrEqual(40);

    // 95th percentile response time must stay under 2 seconds
    times.sort((a, b) => a - b);
    const p95 = times[Math.ceil(times.length * 0.95) - 1];
    console.log(`flood: ${allowed} allowed, ${blocked} blocked, p95 ${p95} ms`);
    expect(p95).toBeLessThan(2000);
  });
});