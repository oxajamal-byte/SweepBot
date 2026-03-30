import re
from collections import defaultdict

_FAILED_SSH_RE = re.compile(r"Failed password|authentication failure", re.IGNORECASE)
_PRIV_ESC_RE = re.compile(r"NOT in sudoers|sudo.*COMMAND=|pam_unix.*root|su\s*\[", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_TIMESTAMP_RE = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_DEST_PORT_RE = re.compile(r"(?:DPT|dport|DPORT)=(\d+)", re.IGNORECASE)

MALICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337}
BRUTE_FORCE_THRESHOLD = 5

# (keyword, severity) — checked after regex rules so we can suppress redundant matches
_KEYWORDS = [
    ("COMMAND=/bin/bash", "critical"),
    ("reverse shell", "critical"),
    ("nc -e", "critical"),
    ("base64 decode", "suspicious"),
]


def read_log(path: str) -> list[tuple[int, str]]:
    lines = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            lines.append((i, line.rstrip()))
    return lines


def _extract_ip(line: str) -> str | None:
    m = _IP_RE.search(line)
    return m.group(1) if m else None


def _extract_timestamp(line: str) -> str | None:
    m = _TIMESTAMP_RE.match(line)
    return m.group(1) if m else None


def check_line(line_num: int, line: str) -> list[dict]:
    flags = []

    def _flag(rule, severity):
        flags.append({
            "line_number": line_num,
            "line": line,
            "timestamp": _extract_timestamp(line),
            "source_ip": _extract_ip(line),
            "rule": rule,
            "severity": severity,
        })

    if _FAILED_SSH_RE.search(line):
        _flag("failed_ssh", "suspicious")

    if _PRIV_ESC_RE.search(line):
        _flag("privilege_escalation", "critical")

    port_match = _DEST_PORT_RE.search(line)
    if port_match:
        try:
            port = int(port_match.group(1))
            if port in MALICIOUS_PORTS:
                _flag(f"malicious_port_{port}", "suspicious")
        except ValueError:
            pass

    already_flagged = {e["rule"] for e in flags}
    for keyword, severity in _KEYWORDS:
        # privilege_escalation already covers COMMAND= lines from sudo context
        if keyword == "COMMAND=/bin/bash" and "privilege_escalation" in already_flagged:
            continue
        if keyword.lower() in line.lower():
            _flag(f"keyword:{keyword}", severity)

    return flags


def detect_brute_force(lines: list[tuple[int, str]]) -> dict[str, list[int]]:
    """Returns IPs that exceed the brute force threshold, mapped to their failed-login line numbers."""
    ip_fail_lines: dict[str, list[int]] = defaultdict(list)
    for line_num, line in lines:
        if _FAILED_SSH_RE.search(line):
            ip = _extract_ip(line)
            if ip:
                ip_fail_lines[ip].append(line_num)
    return {ip: nums for ip, nums in ip_fail_lines.items() if len(nums) > BRUTE_FORCE_THRESHOLD}


def build_report(path: str) -> dict:
    lines = read_log(path)
    entries = []
    rule_counts: dict[str, int] = defaultdict(int)

    for line_num, line in lines:
        for entry in check_line(line_num, line):
            entries.append(entry)
            rule_counts[entry["rule"]] += 1

    # Brute force is a cross-line pattern — add one summary entry per attacking IP
    for ip, line_nums in detect_brute_force(lines).items():
        last_num = line_nums[-1]
        entries.append({
            "line_number": last_num,
            "line": f"[brute_force] {ip} — {len(line_nums)} failed login attempts (lines {line_nums[0]}–{line_nums[-1]})",
            "timestamp": _extract_timestamp(lines[last_num - 1][1]),
            "source_ip": ip,
            "rule": "brute_force",
            "severity": "critical",
        })
        rule_counts["brute_force"] += 1

    entries.sort(key=lambda e: e["line_number"])

    return {
        "file": str(path),
        "total_lines": len(lines),
        "flagged": len(entries),
        "entries": entries,
        "rule_counts": dict(rule_counts),
    }
