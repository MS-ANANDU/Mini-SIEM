import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

FAILED = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*Failed password.*from (?P<ip>[\d.]+)"
)

def detect_bruteforce(path, threshold=5, window=timedelta(minutes=2)):
    attempts = defaultdict(list)
    alerted = set()  # IPs currently in an active burst
    alerts = []
    year = datetime.now().year
    with open(path) as f:
        for line in f:
            m = FAILED.search(line)
            if not m:
                continue
            ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
            ip = m["ip"]
            attempts[ip] = [t for t in attempts[ip] if ts - t <= window] + [ts]
            if len(attempts[ip]) >= threshold and ip not in alerted:
                alerted.add(ip)
                alerts.append({
                    "rule": "SSH Brute Force",
                    "mitre": "T1110",
                    "src_ip": ip,
                    "count": len(attempts[ip]),
                    "time": ts.isoformat(),
                })
            elif len(attempts[ip]) < threshold:
                alerted.discard(ip)  # burst ended, re-arm
    return alerts

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 bruteforce.py <path-to-auth.log>")
        sys.exit(1)
    for alert in detect_bruteforce(sys.argv[1]):
        print(alert)
