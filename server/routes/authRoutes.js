const express = require('express');
const { findUserByUsername } = require('../utils/userStore');
const { generateToken, authenticate } = require('../utils/auth');

function createAuthRouter({ sessions }) {
  const router = express.Router();

  router.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' });
    }

    const user = findUserByUsername(username);
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!user.active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    const token = generateToken();
    sessions[token] = {
      token,
      userId: user.id,
      username: user.username,
      role: user.role,
      expiresAt: Date.now() + 8 * 60 * 60 * 1000,
    };

    console.log(`[AUTH] Login: ${user.username} (${user.role})`);
    return res.json({ token, username: user.username, role: user.role });
  });

  router.post('/logout', (req, res) => {
    const session = authenticate(req, sessions);
    if (!session) return res.status(401).json({ error: 'Unauthorized — please log in' });

    const token = (req.headers.authorization || '').startsWith('Bearer ')
      ? (req.headers.authorization || '').slice(7)
      : null;
    if (token) delete sessions[token];

    return res.json({ message: 'Logged out' });
  });

  router.get('/me', (req, res) => {
    const session = authenticate(req, sessions);
    if (!session) return res.status(401).json({ error: 'Unauthorized — please log in' });
    return res.json({ username: session.username, role: session.role });
  });

  return router;
}

module.exports = createAuthRouter;
