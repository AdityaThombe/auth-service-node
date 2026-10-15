# auth-service-node

A small authentication service: password login, signed session tokens (JWT, HS256) and user profiles.

**Demo target for ProofPatch: intentionally contains security bugs. Never deploy this code.**

| Area | Vulnerability | OWASP |
|---|---|---|
| `src/config.js` | Hardcoded JWT signing secret (CWE-798) | A07 Identification and Authentication Failures |
| `src/auth.js` | Session token decoded without verifying its signature (CWE-347) | A07 Identification and Authentication Failures |
| `src/users.js` | Profile update copies the request body, so a user can make themselves admin (CWE-915) | A01 Broken Access Control |

Run the tests: `npm test` (Node 20+, no dependencies).
