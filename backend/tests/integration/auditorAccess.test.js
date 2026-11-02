// SR-16: Auditor API access-control tests.

const request = require('supertest');

// Mock authentication before loading the application.
jest.mock('../../src/middleware/requireAuth', () => {
  return (req, res, next) => {
    const role = req.headers['x-test-role'];

    if (!role) {
      return res.status(401).json({
        error: 'Not logged in'
      });
    }

    req.user = {
      id: 1,
      role,
      mfaVerified: req.headers['x-test-mfa'] === 'true'
    };

    next();
  };
});

// Mock the restricted database connection.
// These tests verify HTTP permissions without modifying PostgreSQL.
jest.mock('../../src/config/auditReaderDb', () => ({
  query: jest.fn()
}));

const auditReaderDb = require('../../src/config/auditReaderDb');
const app = require('../../src/app');

describe('SR-16: Auditor-only API access', () => {

  beforeEach(() => {
    jest.clearAllMocks();

    auditReaderDb.query.mockResolvedValue({
      rows: []
    });
  });

  test('Unauthenticated users cannot read audit logs', async () => {
    const response = await request(app)
      .get('/api/auditor/logs');

    expect(response.status).toBe(401);
    expect(auditReaderDb.query).not.toHaveBeenCalled();
  });

  test('Voters cannot read audit logs', async () => {
    const response = await request(app)
      .get('/api/auditor/logs')
      .set('x-test-role', 'voter');

    expect(response.status).toBe(403);
    expect(auditReaderDb.query).not.toHaveBeenCalled();
  });

  test('Administrators cannot read audit logs', async () => {
    const response = await request(app)
      .get('/api/auditor/logs')
      .set('x-test-role', 'admin')
      .set('x-test-mfa', 'true');

    expect(response.status).toBe(403);
    expect(auditReaderDb.query).not.toHaveBeenCalled();
  });

  test('Auditors without MFA cannot read audit logs', async () => {
    const response = await request(app)
      .get('/api/auditor/logs')
      .set('x-test-role', 'auditor')
      .set('x-test-mfa', 'false');

    expect(response.status).toBe(403);
    expect(auditReaderDb.query).not.toHaveBeenCalled();
  });

  test('Auditors with MFA can read audit logs', async () => {
    const response = await request(app)
      .get('/api/auditor/logs')
      .set('x-test-role', 'auditor')
      .set('x-test-mfa', 'true');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      records: []
    });

    expect(auditReaderDb.query).toHaveBeenCalledTimes(1);
  });

  test('Auditors with MFA can read integrity alerts', async () => {
    const response = await request(app)
      .get('/api/auditor/integrity-alerts')
      .set('x-test-role', 'auditor')
      .set('x-test-mfa', 'true');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      alerts: []
    });

    expect(auditReaderDb.query).toHaveBeenCalledTimes(1);
  });

  test('Voters cannot read integrity alerts', async () => {
    const response = await request(app)
      .get('/api/auditor/integrity-alerts')
      .set('x-test-role', 'voter');

    expect(response.status).toBe(403);
    expect(auditReaderDb.query).not.toHaveBeenCalled();
  });

});