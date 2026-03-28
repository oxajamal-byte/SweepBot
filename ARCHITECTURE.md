# SweepBot Architecture

## The Problem

If you work in a SOC or do any kind of threat investigation, you already know how repetitive the lookup process is. You get a suspicious IP, and now you're manually checking VirusTotal, then AbuseIPDB, then Shodan, then OTX, copying results between tabs, trying to piece together whether this thing is actually malicious or not. One IP takes 15 to 20 minutes. Now do that 20 times in a shift.

That's what SweepBot fixes.

## What SweepBot Does

You give it an IP address, domain, or file hash. It queries VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX all at once and hands you back one unified report. That's the core of it. On top of that, it can parse through log files and pull out only the entries worth looking at, and it can generate a quick daily threat brief so you're not manually checking feeds every morning.

I built this for SOC analysts and anyone doing threat investigations who are tired of the same repetitive manual process.

## API Keys

SweepBot needs API keys from four services to work. All of them have free tiers.

| Service | What it does | Where to sign up | Free tier |
|---|---|---|---|
| VirusTotal | Malware reports, community scores, file and URL scanning | https://www.virustotal.com/gui/join-us | 500 requests/day |
| AbuseIPDB | IP abuse reports, confidence scores, attack categories | https://www.abuseipdb.com/register | 1,000 checks/day |
| Shodan | Open ports, running services, geolocation, ISP info | https://account.shodan.io/register | 100 queries/month |
| AlienVault OTX | Threat pulses, indicators of compromise, related threats | https://otx.alienvault.com/accounts/signup | Unlimited |

Store your keys in a `.env` file in the project root. This file is in `.gitignore` so it never gets pushed to GitHub.

```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

There's a `.env.example` in the repo that shows the format without any real keys.

## Core Modules

### Module 1: Threat Intel Lookup

This is the main feature. Pass in an IP, domain, or hash and SweepBot fires off requests to all four services at once.

VirusTotal tells you if the IP has been flagged for malware or reported by the community. AbuseIPDB tells you how many times it's been reported for abuse and what kind of attacks it's associated with. Shodan shows you what ports are open, what services are running, where it's located, and who the ISP is. AlienVault OTX checks it against known threat pulses and indicators of compromise.

Everything comes back in one JSON report with each source in its own section so nothing gets mixed together. There's also a risk summary at the top that gives you a quick read on how dangerous this thing actually is.

Input: IP address, domain, or file hash from the command line.
Output: JSON report saved to the reports folder plus a summary printed to the terminal.

### Module 2: Log Parser

Takes a raw log file like syslog, auth.log, or web access logs and runs it through a set of detection rules. Instead of you reading through 10,000 lines trying to find the one that matters, SweepBot flags the suspicious stuff for you.

Things it looks for:
- Repeated failed logins from the same source (brute force patterns)
- Connections to IPs on known threat lists
- Outbound traffic to unusual ports or destinations
- Privilege escalation attempts
- Any patterns that don't match normal baseline activity

Input: path to a log file.
Output: filtered report with only the flagged entries and a note on why each one got flagged.

### Module 3: Daily Threat Brief

Pulls from public threat intelligence feeds and puts together a short summary of what's active right now. Instead of checking RSS feeds, Twitter, and security blogs every morning, you just run this and get a one page overview.

It pulls from AlienVault OTX pulse data, public RSS feeds, and any custom sources you want to add.

Input: nothing, just run it.
Output: a brief covering the top active threats, new indicators of compromise, and what attack methods are trending.

## How a Lookup Works Step by Step

1. You run `python -m sweepbot lookup --ip 185.220.101.34` from the terminal
2. main.py picks up the command through argparse and sends it to threat_lookup.py
3. threat_lookup.py loads the API keys from the .env file using python-dotenv
4. It sends four GET requests at the same time:
   - VirusTotal: `/api/v3/ip_addresses/{ip}`
   - AbuseIPDB: `/api/v2/check` with the IP as a query parameter
   - Shodan: `/shodan/host/{ip}`
   - AlienVault OTX: `/api/v1/indicators/IPv4/{ip}/general`
5. Each API sends back a JSON response. SweepBot pulls out the fields that actually matter from each one
6. Everything gets combined into one report with a calculated risk score
7. The report saves to the reports folder with a timestamp in the filename and a summary prints to the terminal

## Tech Stack

- Python 3
- Requests library for API calls
- python-dotenv for loading API keys securely
- argparse for the command line interface
- JSON for report formatting
- VirusTotal API v3
- AbuseIPDB API v2
- Shodan API
- AlienVault OTX DirectConnect API

## Project Structure

```
SweepBot/
├── README.md
├── ARCHITECTURE.md
├── requirements.txt
├── .env.example
├── .gitignore
├── sweepbot/
│   ├── __init__.py
│   ├── main.py
│   ├── threat_lookup.py
│   ├── log_parser.py
│   ├── threat_brief.py
│   └── utils.py
├── sample_logs/
│   └── example_auth.log
├── reports/
│   └── .gitkeep
└── tests/
    ├── test_lookup.py
    ├── test_parser.py
    └── test_brief.py
```

## Build Order

1. Get the threat intel lookup working first since that's the core of the whole tool
2. Build the log parser with detection rules
3. Add the daily threat brief
4. Wire everything together through one clean CLI
5. Write proper documentation with usage examples and sample output

## Future Features

- Bulk lookups so you can feed it a list of IPs instead of one at a time
- PDF report export for sharing with people who don't want to read JSON
- Webhook alerts when something comes back as high severity
- Custom detection rules for the log parser so users can write their own
- Caching so it doesn't waste API calls looking up the same IP twice
