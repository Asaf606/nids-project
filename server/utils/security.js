const crypto = require('crypto');

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2$${salt}$${hash}`;
}

function isHashedPassword(value) {
  return typeof value === 'string' && value.startsWith('pbkdf2$');
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!isHashedPassword(stored)) return stored === password;
  const [, salt, originalHash] = stored.split('$');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(originalHash, 'hex'));
}

function generateRandomToken(size = 32) {
  return crypto.randomBytes(size).toString('hex');
}

module.exports = {
  hashPassword,
  isHashedPassword,
  verifyPassword,
  generateRandomToken,
};
