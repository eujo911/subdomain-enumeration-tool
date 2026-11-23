#!/usr/bin/env python3
"""
recon.py - Subdomain enumeration + live host probing (subfinder + httpx)

WHAT IT DOES
    1. Enumerates subdomains of a domain with subfinder  -> <domain>.txt
    2. Probes them with httpx to find live hosts         -> <domain>_live.txt
    3. Sends progress/results to Discord, Slack and/or Telegram.

USAGE
    python3 recon.py -d vulnweb.com
    python3 recon.py -d vulnweb.com -o results
    python3 recon.py -d vulnweb.com --discord-webhook "https://discord.com/api/webhooks/..."
    python3 recon.py -d vulnweb.com --telegram-token "123:ABC" --telegram-chat-id "987654"

    Secrets can also come from environment variables:
    DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

REQUIREMENTS
    sudo apt install subfinder httpx-toolkit      (Kali)
    Only run against domains you are authorised to test (e.g. vulnweb.com).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

# A simple pattern for valid domain names like "example.com"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


# ----------------------------- Output helpers ------------------------------
def info(msg):
    print(f"[*] {msg}")


def good(msg):
    print(f"[+] {msg}")


def error(msg):
    print(f"[!] {msg}", file=sys.stderr)


# ------------------------------ CLI arguments ------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Enumerate subdomains with subfinder and probe live hosts with httpx."
    )
    p.add_argument("-d", "--domain", required=True, help="target domain, e.g. vulnweb.com")
    p.add_argument("-o", "--output", default=".",
                   help="output directory (default: current directory)")
    p.add_argument("-t", "--timeout", type=int, default=300,
                   help="max seconds to allow each tool to run (default: 300)")
    # Bonus: notification channels
    p.add_argument("--discord-webhook", default=os.getenv("DISCORD_WEBHOOK_URL"))
    p.add_argument("--slack-webhook", default=os.getenv("SLACK_WEBHOOK_URL"))
    p.add_argument("--telegram-token", default=os.getenv("TELEGRAM_BOT_TOKEN"))
    p.add_argument("--telegram-chat-id", default=os.getenv("TELEGRAM_CHAT_ID"))
    return p.parse_args()


# ------------------------------ Notifications ------------------------------
def post_json(url, payload):
    """POST a JSON payload to a URL using only the standard library."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        # A custom User-Agent avoids Discord/Cloudflare blocking urllib's default one
        headers={"Content-Type": "application/json", "User-Agent": "recon-script/1.0"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status


def notify(args, message):
    """Send a message to every configured channel; failures never stop the scan."""
    message = message[:1800]  # stay under Discord's 2000-char limit
    channels = []
    if args.discord_webhook:
        channels.append(("Discord", args.discord_webhook, {"content": message}))
    if args.slack_webhook:
        channels.append(("Slack", args.slack_webhook, {"text": message}))
    if args.telegram_token and args.telegram_chat_id:
        url = f"https://api.telegram.org/bot{args.telegram_token}/sendMessage"
        channels.append(("Telegram", url,
                         {"chat_id": args.telegram_chat_id, "text": message}))

    for name, url, payload in channels:
        try:
            post_json(url, payload)
            info(f"Notification sent to {name}")
        except (urllib.error.URLError, ValueError, OSError) as exc:
            error(f"Could not notify {name}: {exc}")


# -------------------------------- Tool checks ------------------------------
def find_httpx():
    """Find ProjectDiscovery's httpx (Kali names it httpx-toolkit).
    Python's own 'httpx' package has the same name, so we verify via '-silent'."""
    for name in ("httpx-toolkit", "httpx"):
        path = shutil.which(name)
        if not path:
            continue
        try:
            r = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            continue
        if "-silent" in (r.stdout + r.stderr):
            return path
    return None


# ------------------------------ Core functions -----------------------------
def run_subfinder(domain, timeout):
    """Run subfinder and return a sorted, de-duplicated list of subdomains."""
    cmd = ["subfinder", "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"subfinder timed out after {timeout}s")
    except OSError as exc:
        raise RuntimeError(f"could not run subfinder: {exc}")

    if result.returncode != 0:
        raise RuntimeError(f"subfinder failed: {result.stderr.strip() or 'unknown error'}")

    return sorted({line.strip().lower() for line in result.stdout.splitlines() if line.strip()})


def run_httpx(httpx_bin, infile, timeout):
    """Probe hosts listed in infile; return the list of live URLs."""
    cmd = [httpx_bin, "-l", infile, "-silent", "-no-color"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"httpx timed out after {timeout}s")
    except OSError as exc:
        raise RuntimeError(f"could not run httpx: {exc}")

    if result.returncode != 0:
        raise RuntimeError(f"httpx failed: {result.stderr.strip() or 'unknown error'}")

    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def save_lines(path, lines):
    """Write one item per line to a file."""
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
    except OSError as exc:
        raise RuntimeError(f"cannot write {path}: {exc}")


# ----------------------------------- Main ----------------------------------
def main():
    args = parse_args()
    domain = args.domain.strip().lower()

    # Validate input before running anything
    if not DOMAIN_RE.match(domain):
        error(f"'{args.domain}' does not look like a valid domain.")
        return 1

    # Check the required tools are installed
    if not shutil.which("subfinder"):
        error("subfinder not found. Install it with: sudo apt install subfinder")
        return 1
    httpx_bin = find_httpx()
    if not httpx_bin:
        error("ProjectDiscovery httpx not found. Install it with: sudo apt install httpx-toolkit")
        return 1

    # Make sure the output directory exists
    try:
        os.makedirs(args.output, exist_ok=True)
    except OSError as exc:
        error(f"cannot create output directory '{args.output}': {exc}")
        return 1

    subs_file = os.path.join(args.output, f"{domain}.txt")
    live_file = os.path.join(args.output, f"{domain}_live.txt")

    try:
        # Step 1: enumerate subdomains
        info(f"Step 1/2: enumerating subdomains of {domain} with subfinder...")
        notify(args, f"Recon started for {domain}")
        subdomains = run_subfinder(domain, args.timeout)
        if not subdomains:
            error("No subdomains found. Nothing to probe.")
            notify(args, f"Recon finished for {domain}: no subdomains found")
            return 1
        save_lines(subs_file, subdomains)
        good(f"Found {len(subdomains)} subdomains -> {subs_file}")
        for i, sub in enumerate(subdomains, 1):      # loop: show progress
            print(f"    [{i}/{len(subdomains)}] {sub}")

        # Step 2: probe for live hosts
        info("Step 2/2: probing for live hosts with httpx...")
        live = run_httpx(httpx_bin, subs_file, args.timeout)
        save_lines(live_file, live)
        if live:
            good(f"{len(live)} live hosts -> {live_file}")
            for url in live:
                print(f"    [LIVE] {url}")
        else:                                         # conditional: no live hosts
            info("No live hosts responded.")

        # Bonus: final notification
        summary = (f"Recon finished for {domain}\n"
                   f"Subdomains: {len(subdomains)} | Live: {len(live)}\n" + "\n".join(live))
        notify(args, summary)
        return 0

    except RuntimeError as exc:
        error(str(exc))
        notify(args, f"Recon failed for {domain}: {exc}")
        return 1
    except KeyboardInterrupt:
        error("Interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
