// Unit tests for SR-10 (TLS 1.3 only, and no plain HTTP fallback)

const { buildTlsOptions, getTlsOptions } = require('../../src/config/tls');

describe('SR-10 TLS settings', () => {

  it('only allows TLS 1.3 or newer', () => {
    const options = buildTlsOptions('fake-cert', 'fake-key');
    expect(options.minVersion).toBe('TLSv1.3');
  });

  it('refuses to start if the certificate is missing (no fallback to HTTP)', () => {
    const saved = process.env.TLS_CERT_PATH;
    process.env.TLS_CERT_PATH = 'certs/does-not-exist.pem';

    expect(() => getTlsOptions()).toThrow('TLS certificate or key not found');

    // put it back so nothing else is affected
    process.env.TLS_CERT_PATH = saved;
  });

});