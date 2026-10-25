// SR-19: proves each limiter blocks once its limit is passed.
// Small limits are set BEFORE the module loads so the tests run fast.
process.env.RATE_LIMIT_API_MAX = '3';
process.env.RATE_LIMIT_LOGIN_IP_MAX = '3';
process.env.RATE_LIMIT_LOGIN_ACCOUNT_MAX = '2';

const express = require('express');
const request = require('supertest');
const {
  apiLimiter,
  loginIpLimiter,
  loginAccountLimiter
} = require('../../src/middleware/rateLimiters');

describe('SR-19 rate limiters', () => {
  it('apiLimiter returns 429 once an IP passes the limit', async () => {
    const app = express();
    app.get('/ping', apiLimiter, (req, res) => res.json({ ok: true }));

    for (let i = 0; i < 3; i++) {
      const res = await request(app).get('/ping');
      expect(res.status).toBe(200);
    }
    const blocked = await request(app).get('/ping');
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toMatch(/too many requests/i);
  });

  it('loginIpLimiter returns 429 after too many login attempts from one IP', async () => {
    const app = express();
    app.use(express.json());
    app.post('/login', loginIpLimiter, (req, res) => res.json({ ok: true }));

    for (let i = 0; i < 3; i++) {
      const res = await request(app).post('/login').send({ username: 'a' });
      expect(res.status).toBe(200);
    }
    const blocked = await request(app).post('/login').send({ username: 'a' });
    expect(blocked.status).toBe(429);
  });

  it('loginAccountLimiter blocks one account after failed attempts but not others', async () => {
    const app = express();
    app.use(express.json());
    // A fake login: the password "ok" succeeds, anything else fails with 401
    app.post('/login', loginAccountLimiter, (req, res) => {
      if (req.body.password === 'ok') return res.json({ ok: true });
      return res.status(401).json({ error: 'bad' });
    });

    const bad = { username: 'alice', password: 'wrong' };
    expect((await request(app).post('/login').send(bad)).status).toBe(401);
    expect((await request(app).post('/login').send(bad)).status).toBe(401);
    expect((await request(app).post('/login').send(bad)).status).toBe(429);

    // A different account is not affected
    const other = await request(app)
      .post('/login')
      .send({ username: 'bob', password: 'wrong' });
    expect(other.status).toBe(401);
  });

  it('loginAccountLimiter does not count successful logins', async () => {
    const app = express();
    app.use(express.json());
    app.post('/login', loginAccountLimiter, (req, res) => res.json({ ok: true }));

    for (let i = 0; i < 6; i++) {
      const res = await request(app)
        .post('/login')
        .send({ username: 'carol', password: 'ok' });
      expect(res.status).toBe(200);
    }
  });
});