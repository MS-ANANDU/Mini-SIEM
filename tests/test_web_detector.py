import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from web_detector import detect_web_attacks

def test_detects_sqli(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('192.168.1.105 - - "GET /index.php?id=1\' UNION SELECT null, username FROM users-- HTTP/1.1" 500 412\n')
    alerts = detect_web_attacks(str(p))
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "SQL Injection"

def test_detects_xss(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('192.168.1.88 - - "GET /search?q=<script>alert(\'XSS\')</script> HTTP/1.1" 200 1250\n')
    alerts = detect_web_attacks(str(p))
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Cross-Site Scripting (XSS)"

def test_detects_traversal(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('192.168.1.200 - - "GET /../../etc/passwd HTTP/1.1" 403 199\n')
    alerts = detect_web_attacks(str(p))
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Directory Traversal"

def test_benign_traffic_no_alerts(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('192.168.1.50 - - "GET /index.php?id=1 HTTP/1.1" 200 2326\n')
    assert detect_web_attacks(str(p)) == []
