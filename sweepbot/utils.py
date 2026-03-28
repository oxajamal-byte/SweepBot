import json
from datetime import datetime, timezone
from pathlib import Path

from colorama import init, Fore, Style

init(autoreset=True)

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

_VT_HIGH_THRESHOLD = 5
_ABUSE_HIGH_THRESHOLD = 75
_ABUSE_MODERATE_THRESHOLD = 25

W = 52  


def _c(text, *styles):
    return "".join(styles) + str(text) + Style.RESET_ALL


def _rule(char="─"):
    return _c(char * W, Fore.WHITE + Style.DIM)


def _tag(label, color):
    return _c(f" {label} ", color + Style.BRIGHT)


def _val(text):
    return _c(text if text not in (None, "", []) else "—", Fore.WHITE + Style.BRIGHT)


def _row(label, value, tag=""):
    dim_label = _c(f"  {label:<22}", Style.DIM)
    spacer = "  " if tag else ""
    print(f"{dim_label}{value}{spacer}{tag}")


def _section(title):
    print()
    print(_c(f"  {title}", Fore.WHITE + Style.BRIGHT))
    print(_rule())


def _compute_verdict(report: dict) -> tuple[str, str]:
    vt = report.get("virustotal", {})
    ab = report.get("abuseipdb", {})
    sh = report.get("shodan", {})

    if all("error" in s for s in (vt, ab, sh)):
        return "UNKNOWN", Fore.WHITE

    malicious = vt.get("malicious_votes", 0) if "error" not in vt else 0
    abuse_score = ab.get("abuse_confidence_score", 0) if "error" not in ab else 0
    has_cves = bool(sh.get("vulns")) if "error" not in sh else False

    if malicious >= _VT_HIGH_THRESHOLD or abuse_score >= _ABUSE_HIGH_THRESHOLD or has_cves:
        return "HIGH RISK", Fore.RED
    if malicious > 0 or abuse_score >= _ABUSE_MODERATE_THRESHOLD:
        return "MODERATE RISK", Fore.YELLOW
    return "LOW RISK", Fore.GREEN


def print_banner():
    print()
    print(_c("  S W E E P B O T", Fore.CYAN + Style.BRIGHT))
    print(_c("  " + "─" * 20, Fore.CYAN + Style.DIM))
    print(_c("  threat intelligence toolkit", Style.DIM))
    print()


def print_summary(report: dict):
    ip = report["ip"]
    generated = report["generated_at"]

    print(_rule())
    print(f"  {_c(ip, Fore.CYAN + Style.BRIGHT)}   {_c(generated, Style.DIM)}")
    print(_rule())

    _section("VIRUSTOTAL")
    vt = report.get("virustotal", {})
    if "error" in vt:
        print(_c(f"  {vt['error']}", Fore.RED + Style.DIM))
    else:
        malicious = vt.get("malicious_votes", 0)
        if malicious >= _VT_HIGH_THRESHOLD:
            mal_tag = _tag("FLAGGED", Fore.RED)
        elif malicious > 0:
            mal_tag = _tag("FLAGGED", Fore.YELLOW)
        else:
            mal_tag = _tag("CLEAN", Fore.GREEN)

        _row("malicious votes", _val(malicious), mal_tag)
        _row("suspicious votes", _val(vt.get("suspicious_votes")))
        _row("reputation score", _val(vt.get("reputation_score")))
        _row("country", _val(vt.get("country")))
        asn_val = f"{vt.get('asn', '—')}  ·  {vt.get('as_owner', '—')}"
        _row("asn", _val(asn_val))
        _row("network", _val(vt.get("network")))

    _section("ABUSEIPDB")
    ab = report.get("abuseipdb", {})
    if "error" in ab:
        print(_c(f"  {ab['error']}", Fore.RED + Style.DIM))
    else:
        score = ab.get("abuse_confidence_score", 0)
        if score >= _ABUSE_HIGH_THRESHOLD:
            ab_tag = _tag("HIGH RISK", Fore.RED)
        elif score >= _ABUSE_MODERATE_THRESHOLD:
            ab_tag = _tag("MODERATE", Fore.YELLOW)
        else:
            ab_tag = _tag("CLEAN", Fore.GREEN)

        _row("abuse confidence", _val(f"{score}%"), ab_tag)
        _row("total reports", _val(ab.get("total_reports")))
        _row("distinct reporters", _val(ab.get("num_distinct_users")))
        _row("last reported", _val(ab.get("last_reported_at")))
        _row("isp", _val(ab.get("isp")))
        _row("usage type", _val(ab.get("usage_type")))
        _row("whitelisted", _val(ab.get("is_whitelisted")))

    _section("SHODAN")
    sh = report.get("shodan", {})
    if "error" in sh:
        print(_c(f"  {sh['error']}", Fore.RED + Style.DIM))
    else:
        _row("org", _val(sh.get("org")))
        _row("country", _val(sh.get("country_code")))
        _row("os", _val(sh.get("os")))
        _row("tags", _val(", ".join(sh.get("tags", [])) or None))

        ports = sh.get("open_ports", [])
        _row("open ports", _val(", ".join(str(p) for p in ports) if ports else None))

        vulns = sh.get("vulns", [])
        if vulns:
            _row("cves", _val(", ".join(vulns)), _tag("VULNERABLE", Fore.RED))
        else:
            _row("cves", _val(None), _tag("CLEAN", Fore.GREEN))

        services = sh.get("services", [])
        if services:
            print()
            print(_c("  services", Style.DIM))
            for svc in services:
                product = svc.get("product") or "unknown"
                version = svc.get("version") or ""
                label = f"{product} {version}".strip()
                port_str = _c(f"  ·  {svc['port']}/{svc['transport']}", Fore.CYAN + Style.DIM)
                print(f"{port_str}   {_c(label, Style.DIM)}")

    verdict, color = _compute_verdict(report)
    print()
    print(_rule("═"))
    verdict_line = f"  VERDICT   {_c(verdict, color + Style.BRIGHT)}"
    print(verdict_line)
    print(_rule("═"))
    print()


def save_report(report: dict) -> str:
    REPORTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_ip = report["ip"].replace(".", "_")
    filepath = REPORTS_DIR / f"{safe_ip}_{timestamp}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return str(filepath)
