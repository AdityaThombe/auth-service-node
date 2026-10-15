'use strict';
// Minimal HS256 JSON Web Tokens (node:crypto only).
const crypto = require('node:crypto');

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const hmac = (data, secret) => crypto.createHmac('sha256', secret).update(data).digest('base64url');

function sign(payload, secret) {
  const head = b64({ alg: 'HS256', typ: 'JWT' });
  const body = b64(payload);
  return `${head}.${body}.${hmac(`${head}.${body}`, secret)}`;
}

/** Reads the claims without checking the signature. */
function decode(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    return null;
  }
}

/** Returns the claims only if the signature is valid and the token has not expired. */
function verify(token, secret, now = Date.now()) {
  const [head, body, signature] = String(token).split('.');
  if (!head || !body || !signature) return null;
  const expected = hmac(`${head}.${body}`, secret);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  const claims = decode(token);
  if (!claims || (claims.exp && claims.exp * 1000 < now)) return null;
  return claims;
}

module.exports = { sign, decode, verify };
