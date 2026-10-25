// SR-20: static security analysis. `npm run lint` must pass in CI before merge.
const js = require('@eslint/js');
const globals = require('globals');
const security = require('eslint-plugin-security');

module.exports = [
  { ignores: ['node_modules/**', 'coverage/**'] },
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { sourceType: 'commonjs', ecmaVersion: 2023, globals: { ...globals.node } },
    rules: {
      // Express error handlers must declare all four arguments; ignored catch variables are fine.
      'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none' }],
      // Every rule from the security plugin blocks the build, not just warns.
      ...Object.fromEntries(Object.keys(security.rules).map(name => ['security/' + name, 'error'])),
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error'
    }
  },
  // Reviewed false positives (paths and names come from trusted configuration, not user input):
  {
    files: ['src/config/tls.js', 'scripts/check-audit.js'],
    rules: { 'security/detect-non-literal-fs-filename': 'off' }   // cert paths from .env, CLI file argument
  },
  {
    files: ['src/security/encryption.js'],
    rules: { 'security/detect-object-injection': 'off' }           // env var name built from an integer key version
  },
  {
    files: ['tests/**/*.js'],
    languageOptions: { globals: { ...globals.node, ...globals.jest } },
    rules: {
      'security/detect-non-literal-fs-filename': 'off',
      'security/detect-object-injection': 'off'
    }
  }
];
