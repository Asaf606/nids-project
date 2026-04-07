const crypto = require('crypto');

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function authenticate(req, sessions) {
  const auth = req.headers.authorization || '';
  const bearerToken = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const token = bearerToken || req.query.token || null;
  if (!token) return null;

  const session = sessions[token];
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    delete sessions[token];
    return null;
  }

  return session;
}

function requireAuth(sessions) {
  return (req, res, next) => {
    const session = authenticate(req, sessions);
    if (!session) return res.status(401).json({ error: 'Unauthorized — please log in' });
    req.session = session;
    next();
  };
}

function requireAdmin(sessions) {
  return (req, res, next) => {
    const session = authenticate(req, sessions);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    if (session.role !== 'admin') return res.status(403).json({ error: 'Forbidden — admin only' });
    req.session = session;
    next();
  };
}

module.exports = {
  generateToken,
  authenticate,
  requireAuth,
  requireAdmin,
};
