#!/usr/bin/env python3
"""
What it does
------------
For each SHA-256 you feed it, pulls the VirusTotal v3 file report:
  - detection ratio across AV engines
  - file names the sample is known by
  - tags and file type
  - optional sandbox behaviour summary (--behaviour; doubles request count)

Where to get hashes (free tier has NO full-text search, so feed it hashes):
  1. Hash tools in YOUR lab VM:        sha256sum tool.exe > my_tools.sum
  2. Hash lists from tool repos:       sha256sum output is accepted as-is
     ("hash  ./path/to/file" lines and plain "hash" lines both work)
  3. Hashes quoted in public intrusion reports.

Usage
-----
    pip install requests
    export VT_API_KEY="your-free-key"      # register at virustotal.com
    python3 vt_lookup.py --hash <sha256> [more hashes...]
    python3 vt_lookup.py --hashes-file SharpCollection_sha256.sum
    python3 vt_lookup.py --demo --hashes-file list.sum   # validate file, no API calls
    python3 vt_lookup.py --hashes-file list.sum --behaviour

Output: ./collections/vt/<sha256>.json + console summary
Free tier: 4 requests/minute -> the script sleeps 16s between samples by
default. ~100 hashes takes ~27 min; run it in a background terminal.
"""

import argparse
import datetime
import json
import os
import re
import sys
import time

import requests

API_KEY = os.environ.get("VT_API_KEY", "<REDACTED>")
BASE = "https://www.virustotal.com/api/v3"
OUT_DIR = os.path.join("collections", "vt")
FREE_TIER_SLEEP = 16  # seconds between samples (4/min limit, keep safe margin)
HASH_RE = re.compile(r"[0-9a-f]{64}")


def read_hashes_file(path):
    """Read a hash list. Accepts plain hashes (one per line) AND `sha256sum`
    output ("hash  ./path/to/file"). Returns [(sha256, label), ...], deduped."""
    entries = {}
    with open(path) as f:
        for ln in f:
            line = ln.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            sha = parts[0].lower()
            if not HASH_RE.fullmatch(sha):
                print(f"[!] skipping malformed line: {line[:60]}")
                continue
            label = os.path.basename(parts[1]) if len(parts) > 1 else ""
            entries.setdefault(sha, label)
    return list(entries.items())


def lookup_hash(session, sha256, want_behaviour=False):
    """Fetch the file report and extract hunting-relevant fields."""
    resp = None
    for _ in range(3):
        resp = session.get(f"{BASE}/files/{sha256}", timeout=30)
        if resp.status_code == 404:
            return {"sha256": sha256, "status": "unknown_to_vt"}
        if resp.status_code == 401:
            sys.exit("[!] Unauthorized: check VT_API_KEY")
        if resp.status_code == 429:
            print("    rate limited, sleeping 60s ...")
            time.sleep(60)
            continue
        break
    if resp is None or resp.status_code == 429:
        return {"sha256": sha256, "status": "rate_limited_retries_exhausted"}
    resp.raise_for_status()

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = stats.get("undetected", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0)
    record = {
        "sha256": sha256,
        "status": "ok",
        "fetched_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "detections": f"{stats.get('malicious', 0)}/{total}",
        "names": attrs.get("names", [])[:10],
        "tags": attrs.get("tags", []),
        "type": attrs.get("type_description"),
    }

    if want_behaviour:
        # Behaviour summary is a second (rate-limited) API call per hash.
        b = session.get(f"{BASE}/files/{sha256}/behaviours", timeout=30)
        behaviours = []
        if b.status_code == 200:
            for item in b.json().get("data", []):
                ab = item.get("attributes", {})
                behaviours.append({
                    "sandbox": ab.get("sandbox_name"),
                    "services_created": ab.get("services_created", []) or ab.get("service_creation_events", [])[:5],
                    "files_written": [f.get("path", "") for f in (ab.get("files_written") or [])][:15],
                    "scheduled_tasks": ab.get("scheduled_tasks", [])[:5],
                    "dns": ab.get("dns_lookups", [])[:5],
                })
        record["behaviour"] = behaviours
    return record


def main():
    ap = argparse.ArgumentParser(
        description="VirusTotal file lookup (Week 2 OSINT collection) - "
                    "feeds SHA-256 lists, saves one JSON report per sample")
    ap.add_argument("--hash", nargs="*", help="one or more SHA-256 hashes")
    ap.add_argument("--hashes-file",
                    help="hash list: one hash per line, or sha256sum output")
    ap.add_argument("--behaviour", action="store_true",
                    help="also fetch sandbox behaviour (SECOND API call per hash)")
    ap.add_argument("--sleep", type=float, default=FREE_TIER_SLEEP,
                    help=f"seconds between samples (default {FREE_TIER_SLEEP}; "
                         f"free tier needs >= 15)")
    ap.add_argument("--demo", action="store_true",
                    help="validate setup + hash file, no API calls")
    args = ap.parse_args()

    # build sample list: [(sha256, label)]; accepts plain hashes + sha256sum files
    samples = []
    for h in (args.hash or []):
        h = h.strip().lower()
        if HASH_RE.fullmatch(h):
            samples.append((h, ""))
        else:
            print(f"[!] skipping invalid hash argument: {h[:60]}")
    if args.hashes_file:
        samples += read_hashes_file(args.hashes_file)
    ded = {}
    for sha, label in samples:
        ded.setdefault(sha, label)
    samples = list(ded.items())

    if args.demo:
        print(f"[DEMO] Setup OK. {len(samples)} sample(s) parsed, nothing fetched.")
        print("       Grab lab hashes with:  sha256sum <file> > my_tools.sum")
        return

    if not samples:
        ap.print_help()
        sys.exit("\n[!] Provide --hash <sha256> or --hashes-file <file>")

    if API_KEY == "PASTE-YOUR-FREE-KEY-HERE":
        sys.exit("[!] Set VT_API_KEY (free key from https://virustotal.com)")

    os.makedirs(OUT_DIR, exist_ok=True)
    session = requests.Session()
    session.headers.update({"x-apikey": API_KEY})

    known = 0
    for i, (sha, label) in enumerate(samples):
        name = f"  [{label}]" if label else ""
        print(f"[*] ({i + 1}/{len(samples)}) {sha}{name}")
        try:
            rec = lookup_hash(session, sha, want_behaviour=args.behaviour)
        except requests.RequestException as e:
            rec = {"sha256": sha, "status": f"error: {e}"}
        if label:
            rec["sample_name"] = label

        out_path = os.path.join(OUT_DIR, f"{sha}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False)

        if rec["status"] == "ok":
            known += 1
            print(f"    detections: {rec['detections']}   type: {rec['type']}"
                  f"   tags: {', '.join(rec['tags'][:6])}")
        else:
            print(f"    {rec['status']}")

        if i < len(samples) - 1:
            time.sleep(args.sleep)

    print(f"[+] Done. {known} known / {len(samples) - known} not-found-or-errored "
          f"-> {OUT_DIR}/ (commit as your Week 2 VT increment)")


if __name__ == "__main__":
    main()
