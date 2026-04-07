const path = require('path');
const express = require('express');
const cors = require('cors');
const createAuthRouter = require('./routes/authRoutes');
const createAlertRouter = require('./routes/alertRoutes');
const createAdminRouter = require('./routes/adminRoutes');
const { requireAuth, requireAdmin } = require('./utils/auth');
const { DEFAULT_USERS, USERS_FILE } = require('./utils/userStore');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'dashboard')));

const alerts = [];
const blockedIPs = [];
const firewallRules = [];
const terminatedSessions = [];
const detectionRules = [
  { id: 1, name: 'SSH Port Scan', type: 'signature', enabled: true, severity: 'low', description: 'TCP SYN to port 22' },
  { id: 2, name: 'SQL Injection – SELECT', type: 'signature', enabled: true, severity: 'high', description: 'SELECT keyword in payload' },
  { id: 3, name: 'SYN Flood', type: 'anomaly', enabled: true, threshold: 80, description: 'SYN packets per 10s window' },
  { id: 4, name: 'ICMP Flood', type: 'anomaly', enabled: true, threshold: 60, description: 'ICMP packets per 10s window' },
  { id: 5, name: 'XSS – script tag', type: 'signature', enabled: true, severity: 'high', description: 'script tag in payload' },
  { id: 6, name: 'Brute Force – SSH', type: 'anomaly', enabled: true, threshold: 10, description: 'Auth attempts per 10s window' },
];
const sessions = {};

app.use('/auth', createAuthRouter({ sessions }));
app.use('/alert', createAlertRouter({ alerts, requireAuth: requireAuth(sessions), requireAdmin: requireAdmin(sessions) }));
app.use('/alerts', createAlertRouter({ alerts, requireAuth: requireAuth(sessions), requireAdmin: requireAdmin(sessions) }));
app.use('/admin', createAdminRouter({
  detectionRules,
  blockedIPs,
  firewallRules,
  terminatedSessions,
  sessions,
  requireAuth: requireAuth(sessions),
  requireAdmin: requireAdmin(sessions),
}));

app.listen(PORT, () => {
  console.log(`Zenith backend running on http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/index.html`);
  console.log(`Users file: ${USERS_FILE}`);
  console.log(`Seeded users: ${DEFAULT_USERS.length} (2 admin, 3 analyst)`);
});
