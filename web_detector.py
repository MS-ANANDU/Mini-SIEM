import re
import sys

SIGNATURES = {
    "SQL Injection": [
        r"(?i)(union\s+select|select\s+.*\s+from|or\s+1=1|--|;)",
        r"(?i)(\%27|\'|\%22|\").*(or|and).*(=|\%3d)",
    ],
    "Cross-Site Scripting (XSS)": [
        r"(?i)(<script.*?>.*?</script>|<script|javascript:|onerror\s*=)",
        r"(?i)(alert\(|prompt\(|confirm\()",
    ],
    "Directory Traversal": [
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)",
        r"(?i)(\%2e\%2e\%2f|\%2e\%2e/)",
    ]
}

def detect_web_attacks(path):
    alerts = []
    try:
        with open(path, "r") as f:
            for line_num, line in enumerate(f, 1):
                line_str = line.strip()
                for attack_type, patterns in SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, line_str):
                            alerts.append({
                                "rule": attack_type,
                                "line_number": line_num,
                                "payload": line_str
                            })
                            break
    except FileNotFoundError:
        print(f"[-] Error: File '{path}' not found.")
    return alerts

if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/access.log"
    for alert in detect_web_attacks(log_path):
        print(alert)
