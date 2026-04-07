
# nids-project
Real-time network monitoring and intrusion detection system with automated alerts and dashboard.

# NIDS — Network Intrusion Detection System
**BHOS · System Analysis and Design · CE22.1 · Asaf Novruzov**

---

## What it does

- Captures real network packets using Python + Scapy
- Detects suspicious activity (port scans, SYN floods, SQL injection, high traffic rate)
- Sends alerts to a Node.js backend API
- Shows alerts live in a web dashboard
- Actually It is a lightweight network intrusion detection system that analyzes real-time traffic, detects threats using predefined rules and behavioral patterns, and provides alerts with optional automated response.
--> Compared to Snort, this system is much simpler and not as powerful. However, it is lightweight, easier to understand, and highly customizable. It also includes a real-time dashboard and combines both signature-based and anomaly-based detection. While Snort is designed for enterprise use, this system is more suitable as a prototype or for small-scale environments.However, compared to Snort, this system has limited detection capabilities and is intended as a prototype!!
## Folder structure

```
nids/
├── sniffer/
│   └── sniffer.py       # Python packet capturing and detecting processes
├── server/
│   ├── server.js        # Main Express server
│   ├── package.json
│   ├── data/
│   │   └── users.json   # User credentials (admin & analyst)
│   ├── routes/
│   │   ├── authRoutes.js
│   │   ├── alertRoutes.js
│   │   └── adminRoutes.js
│   └── utils/
│       ├── auth.js
│       └── userStore.js
├── dashboard/
│   └── index.html       # Zenith web dashboard
└── README.md
```

---

## Setup & Run

You need **3 terminal windows** open at the same time.

### Requirements
- Python 3 + pip
- Node.js + npm
- sudo access (Scapy needs root to sniff packets)

---

### Terminal 1 — Install and start backend

```bash
cd server
npm install
node server.js
```


### Terminal 2 — Install Python deps and start sniffer

```bash
cd sniffer
pip3 install scapy requests
sudo python3 sniffer.py
```
-- If you see the problem about python module version please create virtual environment then try these steps-->

-- Create virtual environment
-->python3 -m venv .venv
-- Activate it
-->source .venv/bin/activate
-- Upgrade pip
-->python3 -m pip install --upgrade pip
-- Install required Pyhton packages for sniffign
-->python3 -m pip install scapy requests
-- Run the sniffer with administrator privileges
-->sudo .venv/bin/python3 sniffer.py



 **Note:** `sudo` is required because reading raw network packets needs admin permission.



### Terminal 3 (or browser) — Open dashboard

Open this file in your browser:
```
dashboard/index.html
```



## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/alerts` | Receive alert from sniffer |
| GET | `/alerts` | Get all alerts (newest first, supports filters) |
| GET | `/alerts/count` | Get counts by severity |
| GET | `/alerts/stats` | Get detailed statistics (charts, top IPs, daily data) |
| GET | `/alerts/export` | Export alerts (JSON or CSV) |
| PATCH | `/alerts/:id/status` | Update alert status |
| PATCH | `/alerts/:id/priority` | Update alert priority (admin only) |
| POST | `/alerts/:id/notes` | Add note to alert |
| DELETE | `/alerts/:id` | Delete single alert (admin only) |
| DELETE | `/alerts` | Clear all alerts (admin only) |

### Example — yOU CAN test it with sample as you can see belowww

```bash
curl -X POST http://localhost:3000/alert \
  -H "Content-Type: application/json" \
  -d '{"type":"Test Alert","src_ip":"1.2.3.4","dst_ip":"192.168.1.1","severity":"high","detail":"manual test"}'
```

---

## Detection Rules

The NIDS combines both signature-based and anomaly-based detection techniques to identify suspicious network activity.

---

### Signature-Based Detection

The system inspects packet headers and payloads for known malicious patterns:

- SSH connection attempt (TCP port 22)
- MySQL connection attempt (TCP port 3306)
- FTP connection attempt (TCP port 21)
- DNS requests (UDP port 53)
- TCP SYN-only packets (possible SYN flood pattern)
- ICMP echo requests (possible ICMP flood activity)

- SQL Injection attempt detection (e.g., "SELECT", "DROP", "UNION")
- Cross-Site Scripting (XSS) patterns (e.g., `<script>`, `javascript:`)
- Command injection indicators (e.g., `;`, `&&`, `|`)
- Path traversal attempts (e.g., `../`, `/etc/passwd`)

- Suspicious HTTP payloads (e.g., large Base64-encoded data)
- Possible Command-and-Control (C2) communication patterns
- Suspicious User-Agent strings
- DNS TXT query anomalies

---

### Anomaly-Based Detection

The system monitors traffic behavior to detect abnormal patterns:

- High traffic volume from a single source IP  
  (e.g., more than 20 packets within 10 seconds → potential DoS/DDoS activity)

- Repeated connection attempts (possible brute-force behavior)

- Unusual protocol usage patterns

---

### Alert Severity Levels

Each detected event is categorized based on severity:

- **Low** – Informational or minor suspicious activity  
- **Medium** – Potential threat requiring attention  
- **High** – Likely malicious behavior requiring immediate action  

---


