import os
import concurrent.futures
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

TIMEOUT = 10  

def query_virustotal(ip: str) -> dict:
    """Query VirusTotal v3 for IP reputation data."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        return {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "undetected_votes": stats.get("undetected", 0),
            "reputation_score": data.get("reputation", None),
            "country": data.get("country", None),
            "asn": data.get("asn", None),
            "as_owner": data.get("as_owner", None),
            "network": data.get("network", None),
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB v2 for abuse reports on an IP."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": False}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {})

        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", None),
            "total_reports": data.get("totalReports", None),
            "num_distinct_users": data.get("numDistinctUsers", None),
            "last_reported_at": data.get("lastReportedAt", None),
            "is_whitelisted": data.get("isWhitelisted", None),
            "usage_type": data.get("usageType", None),
            "isp": data.get("isp", None),
            "domain": data.get("domain", None),
            "country_code": data.get("countryCode", None),
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def query_shodan(ip: str) -> dict:
    """Query Shodan for open ports, services, CVEs, and tags."""
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set"}

    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": SHODAN_API_KEY}

    try:
        resp = requests.get(url, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        open_ports = data.get("ports", [])
        services = []
        for item in data.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "cpe": item.get("cpe", []),
            })

        return {
            "org": data.get("org", None),
            "isp": data.get("isp", None),
            "country_code": data.get("country_code", None),
            "city": data.get("city", None),
            "os": data.get("os", None),
            "open_ports": open_ports,
            "services": services,
            "tags": data.get("tags", []),
            "vulns": list(data.get("vulns", {}).keys()),  
            "last_update": data.get("last_update", None),
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"error": "No information available for this IP"}
        if e.response.status_code == 403:
            return {"error": "Free tier limit — upgrade for full results"}
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def run_lookup(ip: str) -> dict:
    """Run all three queries concurrently and return a unified report."""
    queries = {
        "virustotal": query_virustotal,
        "abuseipdb": query_abuseipdb,
        "shodan": query_shodan,
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {source: executor.submit(fn, ip) for source, fn in queries.items()}
        for source, future in futures.items():
            try:
                results[source] = future.result()
            except Exception as e:
                results[source] = {"error": str(e)}

    return {
        "ip": ip,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "virustotal": results["virustotal"],
        "abuseipdb": results["abuseipdb"],
        "shodan": results["shodan"],
    }
