# SweepBot

Threat intelligence lookup tool for SOC analysts and security investigators. Feed it an IP address and it queries VirusTotal, AbuseIPDB, and Shodan at the same time, then gives you one clean report instead of checking three websites manually.

## Why This Exists

Anyone who has done threat investigation knows how repetitive the process is. You get a suspicious IP, you open VirusTotal, check it, open AbuseIPDB, check it again, open Shodan, check it again. Copy the results somewhere. Try to figure out if the thing is actually dangerous. One IP takes 15 to 20 minutes. Do that 20 times in a shift and most of your day is gone.

SweepBot does all of that in one command. Give it an IP, it checks all three sources at the same time, and you get a full report in about 10 seconds.

## Output

![SweepBot Output](assets/sweepbot-output.png)

## Requirements

- Python 3.8 or higher
- pip (comes with Python)
- Free API keys from VirusTotal, AbuseIPDB, and Shodan

## Installation

### Windows

Open Command Prompt or PowerShell.

```bash
git clone https://github.com/oxajamal-byte/SweepBot.git
cd SweepBot
py -m pip install -r requirements.txt
```

If `py` doesn't work, try `python` instead. If neither works, you need to install Python from [python.org](https://www.python.org/downloads/) and make sure you check "Add Python to PATH" during installation.

### macOS

Open Terminal.

```bash
git clone https://github.com/oxajamal-byte/SweepBot.git
cd SweepBot
python3 -m pip install -r requirements.txt
```

If you don't have Python 3 installed, the easiest way is through Homebrew:

```bash
brew install python3
```

### Linux

Open your terminal.

```bash
git clone https://github.com/oxajamal-byte/SweepBot.git
cd SweepBot
python3 -m pip install -r requirements.txt
```

On Debian/Ubuntu, if Python or pip isn't installed:

```bash
sudo apt update
sudo apt install python3 python3-pip
```

On Fedora/RHEL:

```bash
sudo dnf install python3 python3-pip
```

## API Keys

SweepBot needs API keys to talk to the threat intelligence services. All three have free tiers.

Sign up and grab your keys from:
- [VirusTotal](https://www.virustotal.com/gui/join-us) (500 requests/day free)
- [AbuseIPDB](https://www.abuseipdb.com/register) (1,000 checks/day free)
- [Shodan](https://account.shodan.io/register) (100 queries/month free)

Once you have them, copy the example env file and add your keys:

```bash
cp .env.example .env
```

On Windows if `cp` doesn't work:

```bash
copy .env.example .env
```

Open the `.env` file in any text editor and replace the placeholders with your real keys:

```
VIRUSTOTAL_API_KEY=your_actual_key_here
ABUSEIPDB_API_KEY=your_actual_key_here
SHODAN_API_KEY=your_actual_key_here
```

Save it. This file is in `.gitignore` so your keys stay on your machine and never get pushed to GitHub.

## Usage

### Windows

```bash
py -m sweepbot lookup --ip 185.220.101.34
```

### macOS / Linux

```bash
python3 -m sweepbot lookup --ip 185.220.101.34
```

### Options

Skip saving the report to a file:

```bash
python3 -m sweepbot lookup --ip 185.220.101.34 --no-save
```

Reports save to the `reports/` folder automatically as timestamped JSON files. If you want to go back and check a previous investigation, it's all there.

### Run Tests

```bash
python3 -m pytest tests/ -v
```

On Windows use `py` instead of `python3`.

## How It Works

1. You run the command with an IP address
2. SweepBot loads your API keys from the .env file
3. It sends requests to all three APIs at the same time using threads so one slow API doesn't hold up the others
4. Each API sends back JSON data about the IP
5. SweepBot pulls out the important fields from each response and puts them into one report
6. A risk verdict gets calculated from the combined results
7. The report prints to your terminal and saves as a JSON file

If one API is down or throws an error, the other two still run and you still get results. The tool doesn't crash because one source is unavailable.

## What Each Source Checks

**VirusTotal** runs the IP against dozens of antivirus vendors and security tools. It shows how many flagged it as malicious, the reputation score, and what country and network it belongs to.

**AbuseIPDB** is a community database where analysts report IPs that are doing sketchy stuff. It gives you an abuse confidence score from 0 to 100%, how many people reported it, what ISP owns it, and when it was last reported.

**Shodan** scans the internet and keeps track of what services are running on every IP. It shows open ports, what software is on those ports, who owns the IP, and any known vulnerabilities.

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
│   ├── __main__.py
│   ├── main.py
│   ├── threat_lookup.py
│   └── utils.py
├── reports/
│   └── .gitkeep
└── tests/
    └── test_lookup.py
```

## Coming Soon

**Log Parser** that takes raw log files and pulls out suspicious entries like brute force attempts, connections to known bad IPs, and unusual port activity. Instead of reading 10,000 lines of logs yourself, SweepBot flags the ones that matter.

**Daily Threat Brief** that pulls from public threat feeds and puts together a quick summary of what threats are active right now.

**Bulk Lookups** so you can pass in a list of IPs instead of doing them one at a time.

**PDF Export** to generate reports you can share with people who don't want to read JSON.

## Contributing

If you want to add a feature or fix something, open a pull request. Keep the code clean and test anything you add.

## License

MIT License
