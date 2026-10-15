'use strict';
// User store and profile updates.
const { hashPassword } = require('./auth');

function createStore() {
  return new Map();
}

function register(users, username, password, role = 'user') {
  if (users.has(username)) throw new Error('username taken');
  const user = { username, displayName: username, email: '', role, passwordHash: hashPassword(password) };
  users.set(username, user);
  return user;
}

/** PATCH /me: the signed-in user edits their own profile (display name, email). */
function updateProfile(req, user) {
  Object.assign(user, req.body);
  return { username: user.username, displayName: user.displayName, email: user.email, role: user.role };
}

function isAdmin(user) {
  return user?.role === 'admin';
}

module.exports = { createStore, register, updateProfile, isAdmin };
