import logging
import os
import time
from collections import defaultdict

import requests
from scapy.all import DNS, DNSQR, ICMP, IP, Raw, TCP, UDP, sniff

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:3000/alert")
HTTP_PORTS = {80, 8080, 443, 3000}
LOGIN_PATHS = (
    b"POST /AUTH/LOGIN",
    b"POST /LOGIN",
    b"POST /API/LOGIN",
    b"POST /API/AUTH/LOGIN",
)
FAILED_LOGIN_MARKERS = (
    b"401 UNAUTHORIZED",
    b"INVALID CREDENTIALS",
    b"LOGIN FAILED",
    b'"ERROR":"INVALID CREDENTIALS"',
    b'"ERROR":"USERNAME AND PASSWORD REQUIRED"',
)

ip_packet_count = defaultdict(list)
syn_count = defaultdict(list)
icmp_count = defaultdict(list)
login_attempt_count = defaultdict(list)
recent_alerts = defaultdict(float)

DOS_THRESHOLD = 200
SYN_FLOOD_THRESHOLD = 80
ICMP_FLOOD_THRESHOLD = 60
BRUTE_FORCE_THRESHOLD = 5

SIGNATURES = [
    ("Port scan – SSH (22)",
     lambda p: TCP in p and p[TCP].dport == 22 and tcp_flag_set(p, 0x02),
     "low"),
    ("Port scan – FTP (21)",
     lambda p: TCP in p and p[TCP].dport == 21 and tcp_flag_set(p, 0x02),
     "low"),
    ("Port scan – Telnet (23)",
     lambda p: TCP in p and p[TCP].dport == 23 and tcp_flag_set(p, 0x02),
     "low"),
    ("Port scan – MySQL (3306)",
     lambda p: TCP in p and p[TCP].dport == 3306 and tcp_flag_set(p, 0x02),
     "low"),
    ("Port scan – RDP (3389)",
     lambda p: TCP in p and p[TCP].dport == 3389 and tcp_flag_set(p, 0x02),
     "medium"),
    ("Port scan – SMB (445)",
     lambda p: TCP in p and p[TCP].dport == 445 and tcp_flag_set(p, 0x02),
     "medium"),
    ("Port scan – MSSQL (1433)",
     lambda p: TCP in p and p[TCP].dport == 1433 and tcp_flag_set(p, 0x02),
     "low"),

    ("SQL Injection – SELECT keyword",
     lambda p: has_upper_raw(p, b"SELECT"),
     "high"),
    ("SQL Injection – DROP keyword",
     lambda p: has_upper_raw(p, b"DROP"),
     "high"),
    ("SQL Injection – UNION keyword",
     lambda p: has_upper_raw(p, b"UNION"),
     "high"),
    ("SQL Injection – OR 1=1 pattern",
     lambda p: has_upper_raw(p, b"OR 1=1") or has_upper_raw(p, b"' OR '1'='1") or has_upper_raw(p, b'" OR "1"="1'),
     "high"),
    ("SQL Injection – comment bypass (--)",
     lambda p: has_raw(p, b"--"),
     "medium"),

    ("XSS – <script> tag in payload",
     lambda p: has_upper_raw(p, b"<SCRIPT"),
     "high"),
    ("XSS – javascript: URI in payload",
     lambda p: has_upper_raw(p, b"JAVASCRIPT:"),
     "high"),
    ("XSS – onerror/onload event in payload",
     lambda p: has_upper_raw(p, b"ONERROR=") or has_upper_raw(p, b"ONLOAD="),
     "medium"),

    ("Path traversal – ../ in HTTP request",
     lambda p: has_raw(p, b"../") or has_raw(p, b"..\\"),
     "medium"),
    ("Path traversal – /etc/passwd probe",
     lambda p: has_raw(p, b"/etc/passwd"),
     "high"),

    ("Command injection – shell metachar in payload",
     lambda p: any(has_raw(p, token) for token in (b";id", b"|id", b"`id", b";cat", b"|sh", b"&& whoami", b"; whoami")),
     "high"),
    ("Reverse shell attempt",
     lambda p: has_raw(p, b"/bin/sh") or has_raw(p, b"/bin/bash"),
     "high"),

    ("Suspicious User-Agent (curl/wget)",
     lambda p: has_raw(p, b"curl/") or has_raw(p, b"wget/"),
     "low"),
    ("Possible C2 beacon – large Base64 blob in HTTP",
     lambda p: Raw in p and TCP in p and p[TCP].dport in HTTP_PORTS and len(raw_bytes(p)) > 300 and raw_bytes(p).count(b"=") >= 2,
     "medium"),

    ("Brute-force indicator – HTTP 401 Unauthorized in response",
     lambda p: has_upper_raw(p, b"401 UNAUTHORIZED"),
     "medium"),

    ("DNS request observed",
     lambda p: UDP in p and p[UDP].dport == 53,
     "low"),
    ("DNS TXT query – possible data exfiltration",
     lambda p: DNS in p and DNSQR in p and hasattr(p[DNSQR], "qtype") and p[DNSQR].qtype == 16,
     "medium"),

    ("ICMP ping sweep",
     lambda p: ICMP in p and p[ICMP].type == 8,
     "low"),
]


def raw_bytes(pkt):
    if Raw not in pkt:
        return b""
    try:
        return bytes(pkt[Raw].load)
    except Exception:
        return b""


def upper_raw(pkt):
    return raw_bytes(pkt).upper()


def has_raw(pkt, needle):
    return Raw in pkt and needle in raw_bytes(pkt)


def has_upper_raw(pkt, needle):
    return Raw in pkt and needle in upper_raw(pkt)


def tcp_flag_set(pkt, mask):
    if TCP not in pkt:
        return False
    try:
        return (int(pkt[TCP].flags) & mask) == mask
    except Exception:
        return False


def prune_window(store, key, now, window):
    store[key] = [t for t in store[key] if now - t <= window]


def send_alert(alert_type, severity, pkt, detail=None):
    src = pkt[IP].src if IP in pkt else "unknown"
    dst = pkt[IP].dst if IP in pkt else "unknown"
    body = detail or pkt.summary()

    key = f"{alert_type}:{src}:{dst}:{body[:80]}"
    now = time.time()
    if now - recent_alerts[key] < 8:
        return
    recent_alerts[key] = now

    payload = {
        "type": alert_type,
        "src_ip": src,
        "dst_ip": dst,
        "detail": body,
        "severity": severity.lower(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        response = requests.post(BACKEND_URL, json=payload, timeout=2)
        response.raise_for_status()
        log.warning("ALERT [%s]: %s | %s -> %s", severity.upper(), alert_type, src, dst)
    except Exception as e:
        log.error("Could not send alert to backend: %s", e)


def check_dos(pkt, now, src):
    ip_packet_count[src].append(now)
    prune_window(ip_packet_count, src, now, 10)
    if len(ip_packet_count[src]) >= DOS_THRESHOLD:
        send_alert("DoS Attack Detected", "high", pkt, f"{len(ip_packet_count[src])} packets in 10 seconds")
        ip_packet_count[src] = []


def check_syn_flood(pkt, now, src):
    if TCP in pkt and tcp_flag_set(pkt, 0x02):
        syn_count[src].append(now)
        prune_window(syn_count, src, now, 10)
        if len(syn_count[src]) >= SYN_FLOOD_THRESHOLD:
            send_alert("SYN Flood Detected", "high", pkt, f"{len(syn_count[src])} SYN packets in 10 seconds")
            syn_count[src] = []


def check_icmp_flood(pkt, now, src):
    if ICMP in pkt:
        icmp_count[src].append(now)
        prune_window(icmp_count, src, now, 10)
        if len(icmp_count[src]) >= ICMP_FLOOD_THRESHOLD:
            send_alert("ICMP Flood Detected", "high", pkt, f"{len(icmp_count[src])} ICMP packets in 10 seconds")
            icmp_count[src] = []


def check_bruteforce(pkt, now, src, dst):
    if TCP not in pkt or Raw not in pkt:
        return

    payload = upper_raw(pkt)
    tracked = False

    if pkt[TCP].dport in HTTP_PORTS and any(path in payload for path in LOGIN_PATHS):
        tracked = True
    elif pkt[TCP].sport in HTTP_PORTS and any(marker in payload for marker in FAILED_LOGIN_MARKERS):
        tracked = True
    elif pkt[TCP].dport in (21, 22, 23, 3389, 5900, 3306):
        tracked = True

    if not tracked:
        return

    key = f"{src}->{dst}"
    login_attempt_count[key].append(now)
    prune_window(login_attempt_count, key, now, 60)

    if len(login_attempt_count[key]) >= BRUTE_FORCE_THRESHOLD:
        send_alert(
            "Brute Force Attempt",
            "high",
            pkt,
            f"{len(login_attempt_count[key])} suspicious authentication attempts in 60 seconds"
        )
        login_attempt_count[key] = []


def check_signatures(pkt):
    if IP not in pkt:
        return

    for alert_type, rule, severity in SIGNATURES:
        try:
            if rule(pkt):
                send_alert(alert_type, severity, pkt)
        except Exception:
            continue


def process_packet(pkt):
    if IP not in pkt:
        return

    now = time.time()
    src = pkt[IP].src
    dst = pkt[IP].dst

    check_dos(pkt, now, src)
    check_syn_flood(pkt, now, src)
    check_icmp_flood(pkt, now, src)
    check_bruteforce(pkt, now, src, dst)
    check_signatures(pkt)


if __name__ == "__main__":
    log.info("Starting NIDS sniffer... (requires sudo/admin)")
    log.info("Sending alerts to %s", BACKEND_URL)
    log.info("Loaded %s signature rules", len(SIGNATURES))
    sniff(prn=process_packet, store=False)
