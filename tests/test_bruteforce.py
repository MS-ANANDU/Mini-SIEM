import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from bruteforce import detect_bruteforce

LINE = "Oct 15 10:{m:02d}:{s:02d} kali sshd[1]: Failed password for root from {ip} port 22 ssh2\n"

def write_log(tmp_path, ip, count, gap=1):
    p = tmp_path / "auth.log"
    lines = []
    for i in range(count):
        total = i * gap
        lines.append(LINE.format(m=total // 60, s=total % 60, ip=ip))
    p.write_text("".join(lines))
    return str(p)

def test_detects_bruteforce(tmp_path):
    alerts = detect_bruteforce(write_log(tmp_path, "10.0.0.5", 6))
    assert len(alerts) == 1
    assert alerts[0]["mitre"] == "T1110"
    assert alerts[0]["src_ip"] == "10.0.0.5"

def test_below_threshold_no_alert(tmp_path):
    assert detect_bruteforce(write_log(tmp_path, "10.0.0.5", 3)) == []

def test_slow_attempts_no_alert(tmp_path):
    # 6 attempts, 40s apart -> 5 attempts span 160s, never 5 in a 2-minute window
    assert detect_bruteforce(write_log(tmp_path, "10.0.0.5", 6, gap=40)) == []

def test_sustained_attack_alerts_once(tmp_path):
    # 6 attempts, 30s apart: threshold is hit, but the window sliding must not re-alert
    alerts = detect_bruteforce(write_log(tmp_path, "10.0.0.5", 6, gap=30))
    assert len(alerts) == 1
