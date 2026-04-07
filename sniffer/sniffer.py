import time
import requests
import logging
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR

# simple logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

BACKEND_URL = "http://localhost:3000/alert"


ip_packet_count   = defaultdict(list)   # all packets  -> high-traffic DoS
syn_count         = defaultdict(list)   # SYN-only     -> SYN flood
icmp_count        = defaultdict(list)   # ICMP         -> ICMP flood
login_fail_count  = defaultdict(list)   # -> brute force

# Thresholds (per 10-second window)
DOS_THRESHOLD        = 200   # generic high-traffic (was 20 -> way too low!)
SYN_FLOOD_THRESHOLD  = 80    # pure SYN packets
ICMP_FLOOD_THRESHOLD = 60    # ICMP/ping flood
BRUTE_FORCE_THRESHOLD = 10   # repeated auth-port hits


#  SIGNATURE RULES
SIGNATURES = [
    ("Port scan – SSH (22)",
     lambda p: TCP in p and p[TCP].dport == 22 and p[TCP].flags == "S",
     "low"),
    ("Port scan – FTP (21)",
     lambda p: TCP in p and p[TCP].dport == 21 and p[TCP].flags == "S",
     "low"),
    ("Port scan – Telnet (23)",
     lambda p: TCP in p and p[TCP].dport == 23 and p[TCP].flags == "S",
     "low"),
    ("Port scan – MySQL (3306)",
     lambda p: TCP in p and p[TCP].dport == 3306 and p[TCP].flags == "S",
     "low"),
    ("Port scan – RDP (3389)",
     lambda p: TCP in p and p[TCP].dport == 3389 and p[TCP].flags == "S",
     "medium"),
    ("Port scan – SMB (445)",
     lambda p: TCP in p and p[TCP].dport == 445 and p[TCP].flags == "S",
     "medium"),
    ("Port scan – MSSQL (1433)",
     lambda p: TCP in p and p[TCP].dport == 1433 and p[TCP].flags == "S",
     "low"),

    # ── SQL Injection _____________________________________________
    ("SQL Injection – SELECT keyword",
     lambda p: Raw in p and b"SELECT" in bytes(p[Raw].load).upper(),
     "high"),
    ("SQL Injection – DROP keyword",
     lambda p: Raw in p and b"DROP" in bytes(p[Raw].load).upper(),
     "high"),
    ("SQL Injection – UNION keyword",
     lambda p: Raw in p and b"UNION" in bytes(p[Raw].load).upper(),
     "high"),
    ("SQL Injection – OR 1=1 pattern",
     lambda p: Raw in p and b"OR 1=1" in bytes(p[Raw].load).upper(),
     "high"),
    ("SQL Injection – comment bypass (--)",
     lambda p: Raw in p and b"--" in p[Raw].load and TCP in p,
     "medium"),

    # __ XSS __________________________________________________________
    ("XSS – <script> tag in payload",
     lambda p: Raw in p and b"<SCRIPT" in bytes(p[Raw].load).upper(),
     "high"),
    ("XSS – javascript: URI in payload",
     lambda p: Raw in p and b"JAVASCRIPT:" in bytes(p[Raw].load).upper(),
     "high"),
    ("XSS – onerror/onload event in payload",
     lambda p: Raw in p and (b"ONERROR=" in bytes(p[Raw].load).upper()
                              or b"ONLOAD=" in bytes(p[Raw].load).upper()),
     "medium"),

    # __Path Traversal / LFI(Local File InclusioNNN) ___________________
    ("Path traversal – ../ in HTTP request",
     lambda p: Raw in p and b"../" in p[Raw].load and TCP in p,
     "medium"),
    ("Path traversal – /etc/passwd probe",
     lambda p: Raw in p and b"/etc/passwd" in p[Raw].load,
     "high"),

    # ___Command Injection / Shell ______________________________________
    ("Command injection – shell metachar in payload",
     lambda p: Raw in p and any(b in p[Raw].load for b in [b";id", b"|id", b"`id"]),
     "high"),
    ("Reverse shell attempt",
     lambda p: Raw in p and b"/bin/sh" in p[Raw].load,
     "high"),

    # __Malware / C2 indicators _________________________________________
    ("Suspicious User-Agent (curl/wget)",
     lambda p: Raw in p and (b"curl/" in p[Raw].load or b"wget/" in p[Raw].load),
     "low"),
    ("Possible C2 beacon – large Base64 blob in HTTP",
     lambda p: (Raw in p and TCP in p and p[TCP].dport in (80, 8080, 443)
                and len(p[Raw].load) > 300
                and p[Raw].load.count(b"=") >= 2),
     "medium"),

    # __ Brute-force helpers ______________________________________________
    ("Brute-force indicator – HTTP 401 Unauthorized in response",
     lambda p: Raw in p and b"401 Unauthorized" in p[Raw].load,
     "medium"),

    # __ DNS _______________________________________________________________
    ("DNS request observed",
     lambda p: UDP in p and p[UDP].dport == 53,
     "low"),
    ("DNS TXT query – possible data exfiltration",
     lambda p: (DNS in p and DNSQR in p
                and hasattr(p[DNSQR], "qtype") and p[DNSQR].qtype == 16),
     "medium"),

    # ___ ICMP _______________________________________________________________
    ("ICMP ping sweep",
     lambda p: ICMP in p and p[ICMP].type == 8,
     "low"),
]

def block_ip(ip):
    print(f"[FIREWALL] Blocking IP: {ip}")

def send_alert(alert_type, src_ip, dst_ip, detail, severity="medium"):
    payload = {
        "type": alert_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "detail": detail,
        "severity": severity,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        requests.post(BACKEND_URL, json=payload, timeout=2)
        log.warning(f"ALERT [{severity.upper()}]: {alert_type} | {src_ip} -> {dst_ip}")

        if severity == "high":
            block_ip(src_ip)
    except Exception as e:
        log.error(f"Could not send alert to backend: {e}")


def _prune(store, src, window=10):
    """Keep only timestamps within the last `window` seconds, append now, return count."""
    now = time.time()
    store[src] = [t for t in store[src] if now - t < window]
    store[src].append(now)
    return len(store[src])


def check_anomaly(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    #Generic high-traffic DoS
    count = _prune(ip_packet_count, src)
    if count > DOS_THRESHOLD:
        send_alert(
            alert_type="High-traffic DoS (possible flood)",
            src_ip=src, dst_ip=dst,
            detail=f"{count} packets in 10 s (threshold: {DOS_THRESHOLD})",
            severity="high",
        )
        ip_packet_count[src] = []

    if TCP in pkt and pkt[TCP].flags == "S":
        syn = _prune(syn_count, src)
        if syn > SYN_FLOOD_THRESHOLD:
            send_alert(
                alert_type="SYN Flood detected",
                src_ip=src, dst_ip=dst,
                detail=f"{syn} SYN-only packets in 10 s",
                severity="high",
            )
            syn_count[src] = []

    # ─ICMP Flood 
    if ICMP in pkt:
        icmp = _prune(icmp_count, src)
        if icmp > ICMP_FLOOD_THRESHOLD:
            send_alert(
                alert_type="ICMP flood (ping flood)",
                src_ip=src, dst_ip=dst,
                detail=f"{icmp} ICMP packets in 10 s",
                severity="medium",
            )
            icmp_count[src] = []

    # ── Brute-force: repeated hits on auth ports 
    if TCP in pkt and pkt[TCP].dport in (22, 21, 3389, 5900, 23, 3306):
        bf = _prune(login_fail_count, src)
        if bf > BRUTE_FORCE_THRESHOLD:
            port_name = {22: "SSH", 21: "FTP", 3389: "RDP",
                         5900: "VNC", 23: "Telnet", 3306: "MySQL"}.get(
                         pkt[TCP].dport, str(pkt[TCP].dport))
            send_alert(
                alert_type=f"Brute-force attempt – {port_name}",
                src_ip=src, dst_ip=dst,
                detail=f"{bf} connection attempts in 10 s on port {pkt[TCP].dport}",
                severity="high",
            )
            login_fail_count[src] = []


def check_signatures(pkt):
    if IP not in pkt:
        return

    for description, rule, severity in SIGNATURES:
        try:
            if rule(pkt):
                send_alert(
                    alert_type=description,
                    src_ip=pkt[IP].src,
                    dst_ip=pkt[IP].dst,
                    detail=str(pkt.summary()),
                    severity=severity,
                )
                break   
        except Exception:
            pass


def process_packet(pkt):
    check_signatures(pkt)
    check_anomaly(pkt)


if __name__ == "__main__":
    log.info("Starting NIDS sniffer... (requires sudo/admin)")
    log.info(f"Sending alerts to {BACKEND_URL}")
    log.info(f"Loaded {len(SIGNATURES)} signature rules")
    log.info("Press Ctrl+C to stop\n")

    sniff(prn=process_packet, store=False)
