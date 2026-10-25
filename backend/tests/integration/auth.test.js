const request = require('supertest');
const app = require('../../src/app');
const pool = require('../../src/config/db');
const sessionModel = require('../../src/models/sessionModel');

// Reset lockout state so earlier runs don't interfere
beforeAll(async () => {
  await pool.query(
    "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username IN ('voter1','voter2')"
  );
});

afterAll(async () => {
  await pool.pool.end();
});

describe('POST /api/auth/login', () => {
  it('logs in with correct credentials and returns a session token', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'voter1', password: 'Password123!' });
    expect(res.status).toBe(200);
    expect(res.body.sessionToken).toBeDefined();
  });

  it('rejects a wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'voter1', password: 'WrongPassword!' });
    expect(res.status).toBe(401);
  });

  it('rejects an unknown username', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'nobody', password: 'Password123!' });
    expect(res.status).toBe(401);
  });

  it('locks the account after 5 failed attempts', async () => {
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ username: 'voter2', password: 'WrongPassword!' });
    }
    // Even the correct password is now refused
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'voter2', password: 'Password123!' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/locked/i);
  });
});

describe('POST /api/auth/logout', () => {
  it('invalidates the session so the token cannot be reused', async () => {
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'voter1', password: 'Password123!' });
    const token = login.body.sessionToken;

    // The token is valid before logout
    expect(await sessionModel.findValidSession(token)).toBeTruthy();

    const res = await request(app)
      .post('/api/auth/logout')
      .set('x-session-token', token);
    expect(res.status).toBe(200);

    // After logout the same token is no longer valid
    expect(await sessionModel.findValidSession(token)).toBeFalsy();
  });

  it('rejects a logout request with no session token', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(400);
  });
});
