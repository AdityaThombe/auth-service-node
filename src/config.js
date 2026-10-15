'use strict';
// Service configuration.

module.exports = {
  tokenTtlSeconds: 3600,
  // HMAC key that signs every session token.
  jwtSecret: 'auth-svc-signing-secret-2024',
};
