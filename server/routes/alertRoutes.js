const express = require('express');

function createAlertRouter({ alerts, requireAuth, requireAdmin }) {
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
    console.log(`[ALERT #${alert.id}] [${alert.severity.toUpperCase()}] ${alert.type} | ${alert.src_ip} -> ${alert.dst_ip}`);
    return res.status(201).json({ message: 'Alert saved', alert });
  });

  router.get('/', requireAuth, (req, res) => {
    let result = [...alerts].reverse();
    const { severity, from, to, type, ip, status } = req.query;

    if (severity && severity !== 'all') result = result.filter((a) => a.severity === severity);
    if (from) result = result.filter((a) => new Date(a.timestamp) >= new Date(from));
    if (to) {
      const d = new Date(to);
      d.setHours(23, 59, 59, 999);
      result = result.filter((a) => new Date(a.timestamp) <= d);
    }
    if (type) result = result.filter((a) => a.type.toLowerCase().includes(type.toLowerCase()));
    if (ip) result = result.filter((a) => a.src_ip.includes(ip) || a.dst_ip.includes(ip));
    if (status && status !== 'all') result = result.filter((a) => a.status === status);

    return res.json(result);
  });

  router.get('/count', requireAuth, (req, res) => {
    const counts = { total: alerts.length, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      if (counts[a.severity] !== undefined) counts[a.severity] += 1;
    });
    return res.json(counts);
  });

  router.get('/stats', requireAuth, (req, res) => {
    const severity = { high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      if (severity[a.severity] !== undefined) severity[a.severity] += 1;
    });

    const typeCounts = {};
    alerts.forEach((a) => {
      typeCounts[a.type] = (typeCounts[a.type] || 0) + 1;
    });

    const topTypes = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, count]) => ({ name, count }));

    const dayMap = {};
    const now = new Date();
    for (let i = 13; i >= 0; i -= 1) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      dayMap[d.toISOString().slice(0, 10)] = 0;
    }

    alerts.forEach((a) => {
      const day = String(a.timestamp).slice(0, 10);
      if (day in dayMap) dayMap[day] += 1;
    });

    const daily = Object.entries(dayMap).map(([date, count]) => ({ date, count }));

    const ipCounts = {};
    alerts.forEach((a) => {
      ipCounts[a.src_ip] = (ipCounts[a.src_ip] || 0) + 1;
    });

    const topIPs = Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));

    return res.json({ severity, topTypes, daily, topIPs });
  });

  router.get('/export', requireAuth, (req, res) => {
    const format = req.query.format || 'json';
    let result = [...alerts];
    const { severity, from, to } = req.query;

    if (severity && severity !== 'all') result = result.filter((a) => a.severity === severity);
    if (from) result = result.filter((a) => new Date(a.timestamp) >= new Date(from));
    if (to) {
      const d = new Date(to);
      d.setHours(23, 59, 59, 999);
      result = result.filter((a) => new Date(a.timestamp) <= d);
    }

    if (format === 'csv') {
      const header = 'id,severity,type,src_ip,dst_ip,detail,timestamp,status\n';
      const rows = result.map((a) => [
        a.id,
        a.severity,
        `"${a.type}"`,
        a.src_ip,
        a.dst_ip,
        `"${String(a.detail).replace(/"/g, '""')}"`,
        a.timestamp,
        a.status,
      ].join(',')).join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="zenith_alerts_${Date.now()}.csv"`);
      return res.send(header + rows);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="zenith_alerts_${Date.now()}.json"`);
    return res.json(result);
  });

  router.patch('/:id/status', requireAuth, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const { status } = req.body;
    const allowed = req.session.role === 'admin'
      ? ['read', 'under_review', 'false_positive', 'new']
      : ['read', 'under_review'];

    if (!allowed.includes(status)) {
      return res.status(403).json({ error: `Status '${status}' not allowed for your role` });
    }

    alert.status = status;
    if (status === 'false_positive') alert.falsePositive = true;
    return res.json({ message: 'Status updated', alert });
  });

  router.patch('/:id/priority', requireAdmin, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const { priority } = req.body;
    if (!['low', 'normal', 'high', 'critical'].includes(priority)) {
      return res.status(400).json({ error: 'Invalid priority' });
    }

    alert.priority = priority;
    return res.json({ message: 'Priority updated', alert });
  });

  router.post('/:id/notes', requireAuth, (req, res) => {
    const alert = alerts.find((a) => a.id === Number.parseInt(req.params.id, 10));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const { note } = req.body;
    if (!note) return res.status(400).json({ error: 'note is required' });

    const noteObj = {
      author: req.session.username,
      text: note,
      timestamp: new Date().toISOString(),
    };

    alert.notes.push(noteObj);
    return res.json({ message: 'Note added', note: noteObj });
  });

  router.delete('/:id', requireAdmin, (req, res) => {
    const index = alerts.findIndex((a) => a.id === Number.parseInt(req.params.id, 10));
    if (index === -1) return res.status(404).json({ error: 'Alert not found' });
    alerts.splice(index, 1);
    return res.json({ message: 'Alert deleted' });
  });

  router.delete('/', requireAdmin, (req, res) => {
    alerts.length = 0;
    return res.json({ message: 'All alerts cleared' });
  });

  return router;
}

module.exports = createAlertRouter;
