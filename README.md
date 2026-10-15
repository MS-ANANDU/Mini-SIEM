# Mini-SIEM: Python-Based Log Detection Lab

## Objective
A practical, local lab for learning and building defensive Security Information and Event Management (SIEM) log detection rules in a safe, controlled Python environment.

## Technologies
- Python, Kali Linux, Regular Expressions (Regex), Pytest, Git

## Setup Instructions
1. Clone or navigate to your repository directory: `cd ~/pysoc` (or your local path)
2. Install test dependencies: `sudo apt install python3-pytest`
3. Ensure sample log directories exist: `sample_logs/` and `tests/`

## Detection Rules & Modules
- **Rule 1: SSH Brute Force Detection (`bruteforce.py`)**
  Monitors authentication logs for repeated failed password attempts from the same source IP within a sliding time window (MITRE ATT&CK: **T1110**). Features built-in state management to suppress duplicate alerts during sustained attack bursts.
- **Rule 2: Web Log Attack Detection (`web_detector.py`)**
  Parses Apache/Nginx access logs using robust regex signatures to identify common web vector payloads:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Directory Traversal / Path Scanning

## Usage
- Run SSH brute-force detection: `python3 bruteforce.py sample_logs/auth.log`
- Run web log detection: `python3 web_detector.py sample_logs/access.log`
- Run automated unit test suite: `python3 -m pytest -v`

## Learning Outcomes
Understanding log parsing mechanics, sliding window state tracking, signature-based threat detection, writing robust `pytest` unit tests for security rules, and defensive Python programming.
