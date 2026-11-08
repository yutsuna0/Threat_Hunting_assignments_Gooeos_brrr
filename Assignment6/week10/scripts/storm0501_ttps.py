#!/usr/bin/env python3
"""
Usage
-----
    python storm0501_ttps.py                        # full summary
    python storm0501_ttps.py --category AD          # on-prem AD techniques only
    python storm0501_ttps.py --category Cloud       # Entra ID / Azure pivot
    python storm0501_ttps.py --tactic "Credential Access"
    python storm0501_ttps.py --refresh              # re-check attack.mitre.org
"""

import argparse
import csv
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "storm0501_techniques.csv"
OFFICIAL_LAYER_URL = "https://attack.mitre.org/groups/G1053/G1053-enterprise-layer.json"


def load_techniques(path=DATA):
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def print_header(techniques):
    sub = sum(1 for t in techniques if t["is_subtechnique"] == "true")
    print(f"Storm-0501 (MITRE ATT&CK G1053, v1.0, created 2025-10-19)")
    print(f"Documented techniques: {len(techniques)} "
          f"({sub} sub-techniques, {len(techniques) - sub} base techniques)")


def tactic_distribution(techniques):
    counter = Counter()
    for t in techniques:
        for tactic in t["tactics"].split(";"):
            if tactic:
                counter[tactic] += 1
    print("\nTactic distribution (a technique can span several tactics):")
    for tactic, count in counter.most_common():
        bar = "#" * count
        print(f"  {tactic:<26} {count:>3}  {bar}")
    return counter


def category_distribution(techniques):
    counter = Counter(t["category"] for t in techniques)
    total = len(techniques)
    print("\nOperational categories (our mapping for the AD attack topic):")
    for cat, count in counter.most_common():
        print(f"  {cat:<38} {count:>3}  ({count / total:.1%})")
    return counter


def list_techniques(techniques, title):
    print(f"\n{title} ({len(techniques)} techniques):")
    for t in techniques:
        tools = f"  [tools: {t['tool_context']}]" if t["tool_context"] else ""
        print(f"  {t['technique_id']:<11} {t['name']}{tools}")


def refresh(data_path):
    """Pull the live official layer and report new/removed technique IDs."""
    print(f"Fetching {OFFICIAL_LAYER_URL} ...")
    with urllib.request.urlopen(OFFICIAL_LAYER_URL, timeout=30) as response:
        layer = json.load(response)
    live_ids = {t["techniqueID"] for t in layer["techniques"]}
    known = {t["technique_id"] for t in load_techniques()}
    added, removed = live_ids - known, known - live_ids
    print(f"Live layer: {len(live_ids)} techniques | local CSV: {len(known)}")
    if added:
        print("NEW techniques in the live layer (update the CSV):")
        for tid in sorted(added):
            print(f"  + {tid}")
    if removed:
        print("Techniques removed from the live layer:")
        for tid in sorted(removed):
            print(f"  - {tid}")
    if not added and not removed:
        print("Local CSV is in sync with the official layer.")
    return layer


def main():
    parser = argparse.ArgumentParser(description="Storm-0501 TTP analysis.")
    parser.add_argument("--category", help="filter by category substring (e.g. AD, Cloud)")
    parser.add_argument("--tactic", help="filter by tactic substring")
    parser.add_argument("--refresh", action="store_true", help="diff against the live official layer")
    args = parser.parse_args()

    if args.refresh:
        refresh(DATA)
        return 0

    techniques = load_techniques()
    print_header(techniques)
    tactic_distribution(techniques)
    category_distribution(techniques)

    if args.category:
        picked = [t for t in techniques if args.category.lower() in t["category"].lower()]
        list_techniques(picked, f"Techniques in category '{args.category}'")
    elif args.tactic:
        picked = [t for t in techniques if args.tactic.lower() in t["tactics"].lower()]
        list_techniques(picked, f"Techniques under tactic '{args.tactic}'")
    else:
        ad = [t for t in techniques if t["category"].startswith("AD")]
        list_techniques(ad, "On-premises AD techniques (core of our hunting topic)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # e.g. `python storm0501_ttps.py | head` — exit quietly
        sys.exit(0)
