'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { login, authenticate } = require('../src/auth');
const { createStore, register, updateProfile, isAdmin } = require('../src/users');
const jwt = require('../src/jwt');

function setup() {
  const users = createStore();
  register(users, 'alice', 'alice-password-1');
  register(users, 'root', 'root-password-1', 'admin');
  return users;
}

test('login returns a token only for the right password', () => {
  const users = setup();
  assert.ok(login(users, 'alice', 'alice-password-1'));
  assert.strictEqual(login(users, 'alice', 'wrong'), null);
  assert.strictEqual(login(users, 'nobody', 'x'), null);
});

test('a valid token authenticates its user', () => {
  const users = setup();
  const token = login(users, 'alice', 'alice-password-1');
  assert.strictEqual(authenticate({ headers: { authorization: `Bearer ${token}` } }, users).username, 'alice');
});

test('requests without a bearer token are anonymous', () => {
  const users = setup();
  assert.strictEqual(authenticate({ headers: {} }, users), null);
  assert.strictEqual(authenticate({ headers: { authorization: 'Basic abc' } }, users), null);
});

test('jwt.verify rejects a tampered token', () => {
  const token = jwt.sign({ sub: 'alice' }, 'k');
  assert.strictEqual(jwt.verify(token, 'k').sub, 'alice');
  assert.strictEqual(jwt.verify(`${token}x`, 'k'), null);
  assert.strictEqual(jwt.verify(token, 'other-key'), null);
});

test('users can update their display name and email', () => {
  const users = setup();
  const out = updateProfile({ body: { displayName: 'Alice A.', email: 'alice@example.test' } }, users.get('alice'));
  assert.strictEqual(out.displayName, 'Alice A.');
  assert.strictEqual(out.email, 'alice@example.test');
});

test('only admins are admins', () => {
  const users = setup();
  assert.ok(isAdmin(users.get('root')));
  assert.strictEqual(isAdmin(users.get('alice')), false);
});
