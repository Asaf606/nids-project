const express = require('express');
const {
  getUsers,
  createUser,
  updateUser,
  deleteUser,
  findUserById,
} = require('../utils/userStore');

function createAdminRouter({ detectionRules, blockedIPs, firewallRules, terminatedSessions, sessions, requireAuth, requireAdmin }) {
  const router = express.Router();

  router.get('/users', requireAdmin, (req, res) => {
    const users = getUsers().map(({ id, username, role, active, createdAt }) => ({ id, username, role, active, createdAt }));
    return res.json(users);
  });

  router.post('/users', requireAdmin, (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
      return res.status(400).json({ error: 'username, password, role required' });
    }
    if (!['admin', 'analyst'].includes(role)) {
      return res.status(400).json({ error: 'role must be admin or analyst' });
    }

    const result = createUser({ username, password, role });
    if (result.error) return res.status(409).json({ error: result.error });

    console.log(`[ADMIN] User created: ${username} (${role}) by ${req.session.username}`);
    const { user } = result;
    return res.status(201).json({ id: user.id, username: user.username, role: user.role, active: user.active });
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
    if (!['admin', 'analyst'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const user = findUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const updatedUser = updateUser(req.params.id, (currentUser) => ({ ...currentUser, role }));
    Object.keys(sessions).forEach((token) => {
      if (sessions[token].userId === updatedUser.id) sessions[token].role = updatedUser.role;
    });

    return res.json({ message: 'Role updated', username: updatedUser.username, role: updatedUser.role });
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

    return res.json({ message: `User ${updatedUser.active ? 'activated' : 'deactivated'}`, username: updatedUser.username });
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
    console.log(`[ADMIN] IP blocked: ${ip} by ${req.session.username}`);
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
    console.log(`[ADMIN] Firewall rule: ${rule} by ${req.session.username}`);
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
    console.log(`[ADMIN] Session terminated: ${targetUsername} by ${req.session.username}`);
    return res.json({ message: `Session for ${targetUsername} terminated`, entry });
  });

  router.post('/actions/quarantine', requireAdmin, (req, res) => {
    const { ip, note } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip required' });
    const entry = { ip, note: note || 'Quarantined', quarantinedBy: req.session.username, at: new Date().toISOString() };
    console.log(`[ADMIN] IP quarantined: ${ip} by ${req.session.username}`);
    return res.status(201).json({ message: `IP ${ip} quarantined`, entry });
  });

  return router;
}

module.exports = createAdminRouter;
