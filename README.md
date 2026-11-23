# Subdomain Enumeration Tool

A Python-based reconnaissance tool that automates subdomain enumeration and live host detection using Subfinder and ProjectDiscovery httpx.

## Features

- Enumerates subdomains using Subfinder.
- Saves discovered subdomains to `<domain>.txt`.
- Probes discovered subdomains using httpx.
- Saves live hosts to `<domain>_live.txt`.
- Supports command-line arguments for domain and output directory.
- Includes error handling and progress messages.
- Optional notifications through Discord, Slack and Telegram.

## Requirements

- Python 3
- Subfinder
- ProjectDiscovery httpx

## Usage

```bash
python3 recon.py -d vulnweb.com
```

Specify an output directory:

```bash
python3 recon.py -d vulnweb.com -o results
```

## Output

- `vulnweb.com.txt` – Discovered subdomains.
- `vulnweb.com_live.txt` – Live subdomains.

## Disclaimer

Only use this tool against domains you own or have explicit permission to test.