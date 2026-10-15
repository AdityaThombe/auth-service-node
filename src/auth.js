'use strict';
// Login and request authentication.
const crypto = require('node:crypto');
const jwt = require('./jwt');
const config = require('./config');

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const candidate = crypto.scryptSync(password, salt, 32).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(hash));
}

/** Returns a session token for valid credentials, otherwise null. */
function login(users, username, password, now = Date.now()) {
  const user = users.get(username);
  if (!user || !checkPassword(password, user.passwordHash)) return null;
  const exp = Math.floor(now / 1000) + config.tokenTtlSeconds;
  return jwt.sign({ sub: user.username, role: user.role, exp }, config.jwtSecret);
}

/** The user behind an incoming request (Authorization: Bearer <token>), or null. */
function authenticate(req, users) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  const claims = jwt.decode(header.slice(7));
  if (!claims || !claims.sub) return null;
  return users.get(claims.sub) || null;
}

module.exports = { hashPassword, checkPassword, login, authenticate };
