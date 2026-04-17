const express = require('express');
const {
  findUserByUsername,
  findUserByEmail,
  findUserById,
  createUser,
  updateUser,
} = require('../utils/userStore');
const { generateToken, authenticate } = require('../utils/auth');
const { verifyPassword, hashPassword, generateRandomToken } = require('../utils/security');

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    active: user.active,
    emailVerified: user.emailVerified,
    approvedByAdmin: user.approvedByAdmin,
    createdAt: user.createdAt,
    notificationPreferences: user.notificationPreferences,
  };
}

function createAuthRouter({ sessions, verificationTokens, resetTokens, notifications, requireAuth }) {
  const router = express.Router();

  router.post('/register', (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'username, email and password required' });
    }
    const userRole = role === 'guest' ? 'guest' : 'analyst';
    const result = createUser({
      username,
      email,
      password,
      role: userRole,
      active: false,
      emailVerified: false,
      approvedByAdmin: false,
      notificationPreferences: { email: true, sms: false, app: true, criticalOnly: false },
    });
    if (result.error) return res.status(409).json({ error: result.error });

    const { user } = result;
    const token = generateRandomToken(24);
    verificationTokens[token] = { userId: user.id, email: user.email, createdAt: Date.now() };
    notifications.push({
      id: notifications.length + 1,
      userId: user.id,
      channel: 'email',
      type: 'verification',
      destination: user.email,
      message: `Verification link: /auth/verify-email?token=${token}`,
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: 'Registration successful. Verify email and wait for admin approval.',
      verificationToken: token,
      user: sanitizeUser(user),
    });
  });

  router.post('/verify-email', (req, res) => {
    const { token } = req.body;
    const record = verificationTokens[token];
    if (!record) return res.status(400).json({ error: 'Invalid verification token' });

    const user = findUserById(record.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const updatedUser = updateUser(user.id, (current) => ({ ...current, emailVerified: true }));
    delete verificationTokens[token];
    return res.json({ message: 'Email verified successfully', user: sanitizeUser(updatedUser) });
  });

  router.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' });
    }

    const user = findUserByUsername(username) || findUserByEmail(username);
    if (!user || !verifyPassword(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!user.emailVerified) {
      return res.status(403).json({ error: 'Email is not verified' });
    }
    if (!user.approvedByAdmin) {
      return res.status(403).json({ error: 'Account is waiting for admin approval' });
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

    return res.json({ token, username: user.username, role: user.role, email: user.email });
  });

  router.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });
    const user = findUserByEmail(email);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = generateRandomToken(24);
    resetTokens[token] = { userId: user.id, createdAt: Date.now() };
    notifications.push({
      id: notifications.length + 1,
      userId: user.id,
      channel: 'email',
      type: 'password_reset',
      destination: user.email,
      message: `Reset link: /auth/reset-password?token=${token}`,
      createdAt: new Date().toISOString(),
    });

    return res.json({ message: 'Password reset link sent', resetToken: token });
  });

  router.post('/reset-password', (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'token and password required' });
    const record = resetTokens[token];
    if (!record) return res.status(400).json({ error: 'Invalid reset token' });

    const user = findUserById(record.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const updatedUser = updateUser(user.id, (current) => ({ ...current, password: hashPassword(password), active: true }));
    delete resetTokens[token];

    const sessionToken = generateToken();
    sessions[sessionToken] = {
      token: sessionToken,
      userId: updatedUser.id,
      username: updatedUser.username,
      role: updatedUser.role,
      expiresAt: Date.now() + 8 * 60 * 60 * 1000,
    };

    return res.json({ message: 'Password reset successful', token: sessionToken, username: updatedUser.username, role: updatedUser.role, email: updatedUser.email });
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

  router.get('/me', requireAuth, (req, res) => {
    const user = findUserById(req.session.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json(sanitizeUser(user));
  });

  router.get('/notifications', requireAuth, (req, res) => {
    const user = findUserById(req.session.userId);
    const items = notifications.filter((item) => item.userId === user.id || item.userId === null).slice().reverse();
    return res.json({ preferences: user.notificationPreferences, notifications: items });
  });

  router.patch('/notifications/preferences', requireAuth, (req, res) => {
    const { email, sms, app, criticalOnly } = req.body;
    const updatedUser = updateUser(req.session.userId, (current) => ({
      ...current,
      notificationPreferences: {
        email: !!email,
        sms: !!sms,
        app: !!app,
        criticalOnly: !!criticalOnly,
      },
    }));
    return res.json({ message: 'Notification preferences updated', preferences: updatedUser.notificationPreferences });
  });

  return router;
}

module.exports = createAuthRouter;
