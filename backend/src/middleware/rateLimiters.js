// SR-19: Rate limiting.
// Slows down floods and password guessing so real voters can still vote.
// 429 means "Too Many Requests". Limits can be changed from .env so tests can use small numbers.

const rateLimit = require('express-rate-limit');

function readNumber(rawValue, fallback) {
  const value = Number(rawValue);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function tooManyRequests(message) {
  return (req, res) => res.status(429).json({ error: message });
}

// Every /api request: per IP address, per minute.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: readNumber(process.env.RATE_LIMIT_API_MAX, 300),
  standardHeaders: true,
  legacyHeaders: false,
  handler: tooManyRequests('Too many requests. Please slow down.')
});

// Login attempts: per IP address, per 15 minutes.
const loginIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: readNumber(process.env.RATE_LIMIT_LOGIN_IP_MAX, 30),
  standardHeaders: true,
  legacyHeaders: false,
  handler: tooManyRequests('Too many login attempts from this address. Try again later.')
});

// Login attempts: per account (username), per 15 minutes.
// Only failed logins count, so a real voter logging in is never blocked.
// This stops one account being hammered from many different IP addresses.
const loginAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: readNumber(process.env.RATE_LIMIT_LOGIN_ACCOUNT_MAX, 10),
  skipSuccessfulRequests: true,
  keyGenerator: (req) => String((req.body && req.body.username) || 'anonymous').toLowerCase(),
  standardHeaders: true,
  legacyHeaders: false,
  handler: tooManyRequests('Too many failed attempts for this account. Try again later.')
});

module.exports = { apiLimiter, loginIpLimiter, loginAccountLimiter };