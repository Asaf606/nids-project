const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');
const DEFAULT_USERS = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin', active: true, createdAt: '2026-01-01T00:00:00.000Z' },
  { id: 2, username: 'superadmin', password: 'superadmin123', role: 'admin', active: true, createdAt: '2026-01-01T00:00:00.000Z' },
  { id: 3, username: 'analyst1', password: 'analyst123', role: 'analyst', active: true, createdAt: '2026-01-01T00:00:00.000Z' },
  { id: 4, username: 'analyst2', password: 'analyst234', role: 'analyst', active: true, createdAt: '2026-01-01T00:00:00.000Z' },
  { id: 5, username: 'analyst3', password: 'analyst345', role: 'analyst', active: true, createdAt: '2026-01-01T00:00:00.000Z' }
];

function ensureUsersFile() {
  const dir = path.dirname(USERS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(DEFAULT_USERS, null, 2));
  }
}

function readUsers() {
  ensureUsersFile();
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function getUsers() {
  return readUsers();
}

function getNextUserId() {
  const users = readUsers();
  return users.reduce((max, user) => Math.max(max, Number(user.id) || 0), 0) + 1;
}

function findUserByUsername(username) {
  return readUsers().find((user) => user.username === username);
}

function findUserById(id) {
  return readUsers().find((user) => user.id === Number(id));
}

function createUser({ username, password, role }) {
  const users = readUsers();
  if (users.some((user) => user.username === username)) {
    return { error: 'Username already exists' };
  }

  const newUser = {
    id: getNextUserId(),
    username,
    password,
    role,
    active: true,
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);
  writeUsers(users);
  return { user: newUser };
}

function updateUser(id, updater) {
  const users = readUsers();
  const index = users.findIndex((user) => user.id === Number(id));
  if (index === -1) return null;

  const updatedUser = updater({ ...users[index] });
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
  findUserById,
  createUser,
  updateUser,
  deleteUser,
};
