const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static("../dashboard"));

// store alerts in memory (simple array)
// in a real app you'd use a database here
const alerts = [];


//  POST /alert  — sniffer sends alerts here

app.post("/alert", (req, res) => {
  const { type, src_ip, dst_ip, detail, severity, timestamp } = req.body;

  if (!type || !src_ip) {
    return res.status(400).json({ error: "type and src_ip are required" });
  }

  const alert = {
    id: alerts.length + 1,
    type,
    src_ip,
    dst_ip: dst_ip || "unknown",
    detail: detail || "",
    severity: severity || "medium",
    timestamp: timestamp || new Date().toISOString(),
  };

  alerts.push(alert);
  console.log(`[ALERT #${alert.id}] [${alert.severity.toUpperCase()}] ${alert.type} | ${alert.src_ip} -> ${alert.dst_ip}`);
  res.status(201).json({ message: "Alert saved", alert });
});


//  GET /alerts  — dashboard fetches all alerts
//  Optional query params:
//    ?severity=high|medium|low
//    ?from=YYYY-MM-DD
//    ?to=YYYY-MM-DD
//    ?type=keyword  (partial match on alert type)

app.get("/alerts", (req, res) => {
  let result = [...alerts].reverse();

  const { severity, from, to, type } = req.query;

  if (severity && severity !== "all") {
    result = result.filter(a => a.severity === severity);
  }
  if (from) {
    const fromDate = new Date(from);
    result = result.filter(a => new Date(a.timestamp) >= fromDate);
  }
  if (to) {
    const toDate = new Date(to);
    toDate.setHours(23, 59, 59, 999);
    result = result.filter(a => new Date(a.timestamp) <= toDate);
  }
  if (type) {
    const kw = type.toLowerCase();
    result = result.filter(a => a.type.toLowerCase().includes(kw));
  }

  res.json(result);
});


//  GET /alerts/count  — quick count for dashboard badges

app.get("/alerts/count", (req, res) => {
  const counts = { total: alerts.length, high: 0, medium: 0, low: 0 };
  alerts.forEach(a => {
    if (counts[a.severity] !== undefined) counts[a.severity]++;
  });
  res.json(counts);
});


//  GET /alerts/stats  — stats for the dashboard chart
//  Returns: per-day counts, top attack types, severity breakdown

app.get("/alerts/stats", (req, res) => {
  // severity breakdown
  const severity = { high: 0, medium: 0, low: 0 };
  alerts.forEach(a => {
    if (severity[a.severity] !== undefined) severity[a.severity]++;
  });

  // top 6 attack types
  const typeCounts = {};
  alerts.forEach(a => {
    typeCounts[a.type] = (typeCounts[a.type] || 0) + 1;
  });
  const topTypes = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ name, count }));

  // per-day counts (last 14 days)
  const dayMap = {};
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    dayMap[key] = 0;
  }
  alerts.forEach(a => {
    const day = String(a.timestamp).slice(0, 10);
    if (day in dayMap) dayMap[day]++;
  });
  const daily = Object.entries(dayMap).map(([date, count]) => ({ date, count }));

  // top source IPs
  const ipCounts = {};
  alerts.forEach(a => { ipCounts[a.src_ip] = (ipCounts[a.src_ip] || 0) + 1; });
  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, count }));

  res.json({ severity, topTypes, daily, topIPs });
});


//  GET /alerts/export?format=csv|json

app.get("/alerts/export", (req, res) => {
  const format = req.query.format || "json";

  if (format === "csv") {
    const header = "id,severity,type,src_ip,dst_ip,detail,timestamp\n";
    const rows = alerts.map(a =>
      [a.id, a.severity, `"${a.type}"`, a.src_ip, a.dst_ip,
       `"${String(a.detail).replace(/"/g, '""')}"`, a.timestamp].join(",")
    ).join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="nids_alerts_${Date.now()}.csv"`);
    return res.send(header + rows);
  }

  // default JSON
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="nids_alerts_${Date.now()}.json"`);
  res.json(alerts);
});


//  DELETE /alerts  — clear all alerts you can see after that clean window

app.delete("/alerts", (req, res) => {
  alerts.length = 0;
  res.json({ message: "All alerts cleared" });
});

app.listen(PORT, () => {
  console.log(`NIDS backend running on http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/index.html`);
});
