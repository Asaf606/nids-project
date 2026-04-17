const fs = require('fs');
const path = require('path');
const { hashPassword, isHashedPassword } = require('./security');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');
const DEFAULT_USERS = [
  { id: 1, username: 'admin', email: 'admin@zenith.local', password: hashPassword('admin123'), role: 'admin', active: true, emailVerified: true, approvedByAdmin: true, createdAt: '2026-01-01T00:00:00.000Z', notificationPreferences: { email: true, sms: false, app: true, criticalOnly: true } },
  { id: 2, username: 'superadmin', email: 'superadmin@zenith.local', password: hashPassword('superadmin123'), role: 'admin', active: true, emailVerified: true, approvedByAdmin: true, createdAt: '2026-01-01T00:00:00.000Z', notificationPreferences: { email: true, sms: false, app: true, criticalOnly: false } },
  { id: 3, username: 'analyst1', email: 'analyst1@zenith.local', password: hashPassword('analyst123'), role: 'analyst', active: true, emailVerified: true, approvedByAdmin: true, createdAt: '2026-01-01T00:00:00.000Z', notificationPreferences: { email: false, sms: false, app: true, criticalOnly: false } },
  { id: 4, username: 'analyst2', email: 'analyst2@zenith.local', password: hashPassword('analyst234'), role: 'analyst', active: true, emailVerified: true, approvedByAdmin: true, createdAt: '2026-01-01T00:00:00.000Z', notificationPreferences: { email: false, sms: false, app: true, criticalOnly: false } },
  { id: 5, username: 'analyst3', email: 'analyst3@zenith.local', password: hashPassword('analyst345'), role: 'analyst', active: true, emailVerified: true, approvedByAdmin: true, createdAt: '2026-01-01T00:00:00.000Z', notificationPreferences: { email: false, sms: false, app: true, criticalOnly: false } }
];

function ensureUsersFile() {
  const dir = path.dirname(USERS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(DEFAULT_USERS, null, 2));
  }
}

function normalizeUser(user) {
  const normalized = { ...user };
  if (!normalized.email) normalized.email = `${normalized.username}@zenith.local`;
  if (!normalized.role) normalized.role = 'analyst';
  if (!normalized.notificationPreferences) {
    normalized.notificationPreferences = { email: false, sms: false, app: true, criticalOnly: false };
  }
  if (normalized.emailVerified === undefined) normalized.emailVerified = true;
  if (normalized.approvedByAdmin === undefined) normalized.approvedByAdmin = true;
  if (normalized.active === undefined) normalized.active = true;
  if (!normalized.createdAt) normalized.createdAt = new Date().toISOString();
  if (!isHashedPassword(normalized.password)) normalized.password = hashPassword(normalized.password);
  return normalized;
}

function readUsers() {
  ensureUsersFile();
  const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')).map(normalizeUser);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  return users;
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users.map(normalizeUser), null, 2));
}

function getUsers() {
  return readUsers();
}

function getNextUserId() {
  const users = readUsers();
  return users.reduce((max, user) => Math.max(max, Number(user.id) || 0), 0) + 1;
}

function findUserByUsername(username) {
  return readUsers().find((user) => user.username.toLowerCase() === String(username).toLowerCase());
}

function findUserByEmail(email) {
  return readUsers().find((user) => user.email.toLowerCase() === String(email).toLowerCase());
}

function findUserById(id) {
  return readUsers().find((user) => user.id === Number(id));
}

function createUser({ username, email, password, role, active = true, emailVerified = true, approvedByAdmin = true, notificationPreferences }) {
  const users = readUsers();
  if (users.some((user) => user.username.toLowerCase() === String(username).toLowerCase())) {
    return { error: 'Username already exists' };
  }
  if (users.some((user) => user.email.toLowerCase() === String(email).toLowerCase())) {
    return { error: 'Email already exists' };
  }

  const newUser = normalizeUser({
    id: getNextUserId(),
    username,
    email,
    password,
    role,
    active,
    emailVerified,
    approvedByAdmin,
    createdAt: new Date().toISOString(),
    notificationPreferences,
  });

  users.push(newUser);
  writeUsers(users);
  return { user: newUser };
}

function updateUser(id, updater) {
  const users = readUsers();
  const index = users.findIndex((user) => user.id === Number(id));
  if (index === -1) return null;

  const updatedUser = normalizeUser(updater({ ...users[index] }));
  users[index] = updatedUser;
  writeUsers(users);
  return updatedUser;
}

function deleteUser(id) {
  const users = readUsers();
  const index = users.findIndex((user) => user.id === Number(id));
  if (index === -1) return null;

  const [removedUser] = users.splice(index, 1);
  writeUsers(users);
  return removedUser;
}

module.exports = {
  DEFAULT_USERS,
  USERS_FILE,
  getUsers,
  getNextUserId,
  findUserByUsername,
  findUserByEmail,
  findUserById,
  createUser,
  updateUser,
  deleteUser,
  writeUsers,
};
