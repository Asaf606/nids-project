const express = require('express');
const { getUsers } = require('../utils/userStore');

function matchesAlertType(type, filter) {
  if (!filter) return true;
  const lower = String(type).toLowerCase();
  const f = String(filter).toLowerCase();
  const aliases = {
    scan: ['scan'],
    flood: ['flood'],
    sql: ['sql'],
    xss: ['xss'],
    brute: ['brute'],
  };
  return (aliases[f] || [f]).some((term) => lower.includes(term));
}

function addAuditEntry(auditTrail, alertId, actor, action, changes = {}) {
  auditTrail.push({
    id: auditTrail.length + 1,
    alertId,
    actor,
    action,
    changes,
    timestamp: new Date().toISOString(),
  });
}

function createAlertRouter({ alerts, auditTrail, notifications, requireAuth, requireAdmin }) {
  const router = express.Router();

  router.post('/', (req, res) => {
    const { type, src_ip, dst_ip, detail, severity, timestamp } = req.body;
    if (!type || !src_ip) {
      return res.status(400).json({ error: 'type and src_ip are required' });
    }

    const alert = {
      id: alerts.length + 1,
      type,
      src_ip,
      dst_ip: dst_ip || 'unknown',
      detail: detail || '',
      severity: severity || 'medium',
      timestamp: timestamp || new Date().toISOString(),
      status: 'new',
      priority: 'normal',
      notes: [],
      falsePositive: false,
    };

    alerts.push(alert);
    addAuditEntry(auditTrail, alert.id, 'system', 'created', { severity: alert.severity, type: alert.type });

    if (['high', 'critical'].includes(alert.severity)) {
      const users = getUsers().filter((user) => user.active && user.emailVerified && user.approvedByAdmin);
      users.forEach((user) => {
        const prefs = user.notificationPreferences || {};
        const channels = [];
        if (prefs.app) channels.push('app');
        if (prefs.email) channels.push('email');
        if (prefs.sms) channels.push('sms');
        channels.forEach((channel) => {
          notifications.push({
            id: notifications.length + 1,
            userId: user.id,
            channel,
            type: 'critical_alert',
            destination: channel === 'email' ? user.email : `${user.username}:${channel}`,
            message: `Critical alert #${alert.id}: ${alert.type}`,
            createdAt: new Date().toISOString(),
          });
        });
      });
    }

    return res.status(201).json({ message: 'Alert saved', alert });
  });

  router.get('/', requireAuth, (req, res) => {
    let result = [...alerts].reverse();
    const { severity, from, to, type, ip, status } = req.query;

    if (req.session.role === 'guest') {
      result = result.filter((a) => ['low', 'medium'].includes(a.severity));
    }

    if (severity && severity !== 'all') result = result.filter((a) => a.severity === severity);
    if (from) result = result.filter((a) => new Date(a.timestamp) >= new Date(from));
    if (to) {
      const d = new Date(to);
      d.setHours(23, 59, 59, 999);
      result = result.filter((a) => new Date(a.timestamp) <= d);
    }
    if (type) result = result.filter((a) => matchesAlertType(a.type, type));
    if (ip) result = result.filter((a) => a.src_ip.includes(ip) || a.dst_ip.includes(ip));
    if (status && status !== 'all') result = result.filter((a) => a.status === status);

    return res.json(result);
  });

  router.get('/stats', requireAuth, (req, res) => {
    let visibleAlerts = [...alerts];
    if (req.session.role === 'guest') {
      visibleAlerts = visibleAlerts.filter((a) => ['low', 'medium'].includes(a.severity));
    }

    const severity = { high: 0, medium: 0, low: 0 };
    visibleAlerts.forEach((a) => {
      if (severity[a.severity] !== undefined) severity[a.severity] += 1;
    });

    const typeCounts = {};
    visibleAlerts.forEach((a) => {
      typeCounts[a.type] = (typeCounts[a.type] || 0) + 1;
    });

    const topTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([name, count]) => ({ name, count }));

    const dayMap = {};
    const now = new Date();
    for (let i = 13; i >= 0; i -= 1) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      dayMap[d.toISOString().slice(0, 10)] = 0;
    }

    visibleAlerts.forEach((a) => {
      const day = String(a.timestamp).slice(0, 10);
      if (day in dayMap) dayMap[day] += 1;
    });

    const daily = Object.entries(dayMap).map(([date, count]) => ({ date, count }));
    const ipCounts = {};
    visibleAlerts.forEach((a) => {
      ipCounts[a.src_ip] = (ipCounts[a.src_ip] || 0) + 1;
    });
    const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count }));

    return res.json({ severity, topTypes, daily, topIPs });
  });

  router.get('/export', requireAuth, (req, res) => {
    const format = req.query.format || 'json';
    let result = [...alerts];
    const { severity, from, to } = req.query;

    if (req.session.role === 'guest') result = result.filter((a) => ['low', 'medium'].includes(a.severity));
    if (severity && severity !== 'all') result = result.filter((a) => a.severity === severity);
    if (from) result = result.filter((a) => new Date(a.timestamp) >= new Date(from));
    if (to) {
      const d = new Date(to);
      d.setHours(23, 59, 59, 999);
      result = result.filter((a) => new Date(a.timestamp) <= d);
    }

    if (format === 'csv') {
      const header = 'id,severity,type,src_ip,dst_ip,detail,timestamp,status\n';
      const rows = result.map((a) => [a.id, a.severity, `"${a.type}"`, a.src_ip, a.dst_ip, `"${String(a.detail).replace(/"/g, '""')}"`, a.timestamp, a.status].join(',')).join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="zenith_alerts_${Date.now()}.csv"`);
      return res.send(header + rows);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="zenith_alerts_${Date.now()}.json"`);
    return res.json(result);
  });

  router.get('/:id/audit-trail', requireAuth, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    return res.json(auditTrail.filter((entry) => entry.alertId === alert.id).slice().reverse());
  });

  router.patch('/:id/status', requireAuth, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const { status } = req.body;
    const allowed = req.session.role === 'admin'
      ? ['read', 'under_review', 'false_positive', 'new']
      : ['read', 'under_review'];

    if (!allowed.includes(status)) return res.status(403).json({ error: `Status '${status}' not allowed for your role` });
    const previous = alert.status;
    alert.status = status;
    if (status === 'false_positive') alert.falsePositive = true;
    addAuditEntry(auditTrail, alert.id, req.session.username, 'status_updated', { from: previous, to: status });
    return res.json({ message: 'Status updated', alert });
  });

  router.patch('/:id/priority', requireAdmin, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const { priority } = req.body;
    if (!['low', 'normal', 'high', 'critical'].includes(priority)) return res.status(400).json({ error: 'Invalid priority' });
    const previous = alert.priority;
    alert.priority = priority;
    addAuditEntry(auditTrail, alert.id, req.session.username, 'priority_updated', { from: previous, to: priority });
    return res.json({ message: 'Priority updated', alert });
  });

  router.post('/:id/notes', requireAuth, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const { note } = req.body;
    if (!note) return res.status(400).json({ error: 'note is required' });

    const noteObj = { author: req.session.username, text: note, timestamp: new Date().toISOString() };
    alert.notes.push(noteObj);
    addAuditEntry(auditTrail, alert.id, req.session.username, 'note_added', { note });
    return res.json({ message: 'Note added', note: noteObj });
  });

  router.delete('/:id', requireAdmin, (req, res) => {
    const index = alerts.findIndex((a) => a.id === Number.parseInt(req.params.id, 10));
    if (index === -1) return res.status(404).json({ error: 'Alert not found' });
    const [removed] = alerts.splice(index, 1);
    addAuditEntry(auditTrail, removed.id, req.session.username, 'deleted', {});
    return res.json({ message: 'Alert deleted' });
  });

  router.delete('/', requireAdmin, (req, res) => {
    alerts.forEach((alert) => addAuditEntry(auditTrail, alert.id, req.session.username, 'deleted', {}));
    alerts.length = 0;
    return res.json({ message: 'All alerts cleared' });
  });

  return router;
}

module.exports = createAlertRouter;
