// SR-07: the login route must reject malformed input with 400
// before it does any database lookup.

const request = require('supertest');
const app = require('../../src/app');
const pool = require('../../src/config/db');

afterAll(async () => {
  await pool.pool.end();
});

describe('SR-07 login input validation', () => {
  const badBodies = [
    ['an empty body', undefined],
    ['a missing password', { username: 'voter1' }],
    ['a missing username', { password: 'Password123!' }],
    ['an object as the username (injection-style)', { username: { $ne: null }, password: 'x' }],
    ['an array as the password', { username: 'voter1', password: ['a', 'b'] }],
    ['a number as the username', { username: 123, password: 'x' }],
    ['an oversized username', { username: 'a'.repeat(101), password: 'x' }],
    ['an oversized password', { username: 'voter1', password: 'p'.repeat(201) }],
    ['an unexpected extra field', { username: 'voter1', password: 'Password123!', role: 'admin' }],
    ['empty strings', { username: '', password: '' }],
  ];

  test.each(badBodies)('rejects %s with 400 and no session', async (_name, body) => {
    const res = await request(app).post('/api/auth/login').send(body);

    expect(res.status).toBe(400);
    expect(res.body.sessionToken).toBeUndefined();
  });
});