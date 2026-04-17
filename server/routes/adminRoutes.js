const express = require('express');
const {
  getUsers,
  createUser,
  updateUser,
  deleteUser,
  findUserById,
} = require('../utils/userStore');

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

function createAdminRouter({ detectionRules, blockedIPs, firewallRules, terminatedSessions, sessions, requireAuth, requireAdmin, notifications }) {
  const router = express.Router();

  router.get('/users', requireAdmin, (req, res) => {
    return res.json(getUsers().map(sanitizeUser));
  });

  router.get('/users/pending', requireAdmin, (req, res) => {
    return res.json(getUsers().filter((user) => !user.approvedByAdmin || !user.emailVerified).map(sanitizeUser));
  });

  router.post('/users', requireAdmin, (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password || !role) {
      return res.status(400).json({ error: 'username, email, password, role required' });
    }
    if (!['admin', 'analyst', 'guest'].includes(role)) {
      return res.status(400).json({ error: 'role must be admin, analyst or guest' });
    }

    const result = createUser({
      username,
      email,
      password,
      role,
      active: true,
      emailVerified: true,
      approvedByAdmin: true,
      notificationPreferences: { email: false, sms: false, app: true, criticalOnly: false },
    });
    if (result.error) return res.status(409).json({ error: result.error });

    const { user } = result;
    return res.status(201).json(sanitizeUser(user));
  });

  router.patch('/users/:id/approve', requireAdmin, (req, res) => {
    const user = findUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const updatedUser = updateUser(req.params.id, (current) => ({ ...current, approvedByAdmin: true, active: current.emailVerified }));
    notifications.push({
      id: notifications.length + 1,
      userId: updatedUser.id,
      channel: 'app',
      type: 'account_approved',
      destination: updatedUser.username,
      message: 'Your account has been approved by admin',
      createdAt: new Date().toISOString(),
    });
    return res.json({ message: 'User approved', user: sanitizeUser(updatedUser) });
  });

  router.delete('/users/:id', requireAdmin, (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    if (id === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
    const removedUser = deleteUser(id);
    if (!removedUser) return res.status(404).json({ error: 'User not found' });
    Object.keys(sessions).forEach((token) => {
      if (sessions[token].userId === id) delete sessions[token];
    });
    return res.json({ message: `User ${removedUser.username} deleted` });
  });

  router.patch('/users/:id/role', requireAdmin, (req, res) => {
    const { role } = req.body;
    if (!['admin', 'analyst', 'guest'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const user = findUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const updatedUser = updateUser(req.params.id, (currentUser) => ({ ...currentUser, role }));
    Object.keys(sessions).forEach((token) => {
      if (sessions[token].userId === updatedUser.id) sessions[token].role = updatedUser.role;
    });
    return res.json({ message: 'Role updated', user: sanitizeUser(updatedUser) });
  });

  router.patch('/users/:id/status', requireAdmin, (req, res) => {
    const user = findUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.id === req.session.userId) return res.status(400).json({ error: 'Cannot deactivate yourself' });
    const updatedUser = updateUser(req.params.id, (currentUser) => ({ ...currentUser, active: !!req.body.active }));
    if (!updatedUser.active) {
      Object.keys(sessions).forEach((token) => {
        if (sessions[token].userId === updatedUser.id) delete sessions[token];
      });
    }
    return res.json({ message: `User ${updatedUser.active ? 'activated' : 'deactivated'}`, user: sanitizeUser(updatedUser) });
  });

  router.get('/rules', requireAuth, (req, res) => res.json(detectionRules));

  router.post('/rules', requireAdmin, (req, res) => {
    const { name, type, description, severity, threshold } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'name and type required' });
    const rule = { id: detectionRules.length ? Math.max(...detectionRules.map((item) => item.id)) + 1 : 1, name, type, enabled: true, description: description || '', severity: severity || 'medium', threshold: threshold || null };
    detectionRules.push(rule);
    return res.status(201).json(rule);
  });

  router.patch('/rules/:id', requireAdmin, (req, res) => {
    const rule = detectionRules.find((item) => item.id === Number.parseInt(req.params.id, 10));
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    const { name, description, severity, threshold } = req.body;
    if (name) rule.name = name;
    if (description !== undefined) rule.description = description;
    if (severity) rule.severity = severity;
    if (threshold !== undefined) rule.threshold = threshold;
    return res.json(rule);
  });

  router.patch('/rules/:id/toggle', requireAdmin, (req, res) => {
    const rule = detectionRules.find((item) => item.id === Number.parseInt(req.params.id, 10));
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    rule.enabled = !rule.enabled;
    return res.json({ message: `Rule ${rule.enabled ? 'enabled' : 'disabled'}`, rule });
  });

  router.patch('/rules/:id/threshold', requireAdmin, (req, res) => {
    const rule = detectionRules.find((item) => item.id === Number.parseInt(req.params.id, 10));
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    const { threshold } = req.body;
    if (typeof threshold !== 'number') return res.status(400).json({ error: 'threshold must be a number' });
    rule.threshold = threshold;
    return res.json({ message: 'Threshold updated', rule });
  });

  router.get('/actions/blocked-ips', requireAdmin, (req, res) => res.json(blockedIPs));
  router.post('/actions/block-ip', requireAdmin, (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip required' });
    if (blockedIPs.find((item) => item.ip === ip)) return res.status(409).json({ error: 'IP already blocked' });
    const entry = { ip, reason: reason || 'Manually blocked', blockedBy: req.session.username, blockedAt: new Date().toISOString() };
    blockedIPs.push(entry);
    return res.status(201).json({ message: `IP ${ip} blocked`, entry });
  });
  router.delete('/actions/block-ip/:ip', requireAdmin, (req, res) => {
    const index = blockedIPs.findIndex((item) => item.ip === req.params.ip);
    if (index === -1) return res.status(404).json({ error: 'IP not in block list' });
    blockedIPs.splice(index, 1);
    return res.json({ message: `IP ${req.params.ip} unblocked` });
  });
  router.get('/actions/firewall-rules', requireAdmin, (req, res) => res.json(firewallRules));
  router.post('/actions/firewall-rule', requireAdmin, (req, res) => {
    const { rule, description } = req.body;
    if (!rule) return res.status(400).json({ error: 'rule required' });
    const entry = { id: firewallRules.length + 1, rule, description: description || '', createdBy: req.session.username, createdAt: new Date().toISOString() };
    firewallRules.push(entry);
    return res.status(201).json({ message: 'Firewall rule triggered', entry });
  });
  router.post('/actions/terminate-session', requireAdmin, (req, res) => {
    const { targetUsername, reason } = req.body;
    if (!targetUsername) return res.status(400).json({ error: 'targetUsername required' });
    Object.keys(sessions).forEach((token) => {
      if (sessions[token].username === targetUsername) delete sessions[token];
    });
    const entry = { targetUsername, reason: reason || 'Terminated by admin', terminatedBy: req.session.username, at: new Date().toISOString() };
    terminatedSessions.push(entry);
    return res.json({ message: `Session for ${targetUsername} terminated`, entry });
  });
  router.post('/actions/quarantine', requireAdmin, (req, res) => {
    const { ip, note } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip required' });
    const entry = { ip, note: note || 'Quarantined', quarantinedBy: req.session.username, at: new Date().toISOString() };
    return res.status(201).json({ message: `IP ${ip} quarantined`, entry });
  });

  return router;
}

module.exports = createAdminRouter;
