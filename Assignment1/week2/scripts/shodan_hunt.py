#!/usr/bin/env python3
"""
What it does
------------
Runs a fixed set of Shodan queries that surface internet-facing hosts running
Active Directory core services (Kerberos 88, LDAP 389/636, Global Catalog
3268/3269, SMB 445) and saves every result set with full provenance
(source, query, timestamp) into JSON + a summary CSV.

Setup
-----
    pip install shodan
    export SHODAN_API_KEY="your-free-key"     # register at shodan.io
    python3 shodan_hunt.py --dry-run          # print queries, no API calls
    python3 shodan_hunt.py                    # run all queries
    python3 shodan_hunt.py --query 'port:389 "namingContexts" country:KZ'
    python3 shodan_hunt.py --self-audit example-corp.com

Output: ./collections/shodan/<query_id>.json + ./collections/shodan/summary.csv
"""

import argparse
import csv
import datetime
import json
import os
import sys
import time
from pathlib import Path

try:
    import shodan
except ImportError:
    shodan = None  # allowed for --dry-run; checked again before API calls

API_KEY = os.environ.get("SHODAN_API_KEY", "<REDACTED>")
OUT_DIR = os.path.join("collections", "shodan")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IOC_FILES = [
    SCRIPT_DIR.parent / "references" / "impacket_iocs_high.json",
    SCRIPT_DIR / "impacket_iocs_high.json",
    Path("impacket_iocs_high.json"),
]


def load_high_iocs(path_override=None):
    """Load curated high-relevance IoC set -> list of entries (id, title, grep_tokens)."""
    candidates = [Path(path_override)] if path_override else DEFAULT_IOC_FILES
    for p in candidates:
        if p and p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                iocs = [i for i in data.get("iocs", []) if i.get("grep_tokens")]
                if iocs:
                    meta = data.get("meta", {})
                    return iocs, str(p), meta.get("total_iocs", len(iocs))
            except (json.JSONDecodeError, OSError) as e:
                print(f"[!] Could not parse {p}: {e}")
    return None, None, 0

# ---------------------------------------------------------------------------
# Query set. Why these queries (write-up in Week2.md):
#   - port 389/636  : LDAP/LDAPS - AD-native. rootDSE answers leak
#                     namingContexts (DC=corp,...) -> reveals domain structure
#   - ssl.cert      : certificates often carry DC hostnames in CN/SAN fields
#   - port 3268     : Global Catalog - AD-ONLY service, so any hit is
#                     basically a domain controller on the internet
#   - port 88       : Kerberos - AD-native auth service (Microsoft product
#                     filter keeps the hits in Windows-land)
#   - port 445      : SMB - AD-ADJACENT, not AD-native. Any Windows box has
#                     it, but it stays in scope because it is THE lateral
#                     movement vector our Impacket IoC set rides on
#                     (smbexec/psexec/secretsdump all speak 445).
# AD-native = service exists to serve the domain. AD-adjacent = generic
# service that AD attacks depend on. Defend the difference if asked.
# The self-audit query (org filter) is the defensive mirror of the same idea;
# port 53 is included because AD-integrated DNS lives on DCs.
# ---------------------------------------------------------------------------
QUERIES = {
    "ldap_rootdse":   'port:389 "namingContexts"',
    "ldaps_certs":    'port:636 ssl.cert.subject.CN:dc*',
    "global_catalog": 'port:3268',
    "kerberos_88":    'port:88 product:"Microsoft Windows" -google -microsoft',
    "smb_445":        'port:445 os:"Windows Server" -google -microsoft',
}

RESULTS_PER_QUERY = 100   # free API caps search results at 100/page
RATE_LIMIT_SLEEP = 1.2    # free tier: ~1 request/second


def ensure_out_dir():
    os.makedirs(OUT_DIR, exist_ok=True)


def tag_banner(hit_record, high_iocs):
    """Match a result's banner/hostnames/ssl CN against curated IoC tokens."""
    blob = json.dumps(hit_record).lower()
    hits = {}
    for ioc in high_iocs:
        matched = [t for t in ioc.get("grep_tokens", []) if t and t in blob]
        if matched:
            hits[ioc["id"]] = matched
    return hits


def run_query(api, query_id, query, results_limit, high_iocs=None):
    """Run one Shodan search, persist JSON with provenance, return rows."""
    print(f"[*] {query_id}: {query}")
    result = api.search(query, limit=results_limit)

    record = {
        "query_id": query_id,
        "query": query,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_shodan_index": result.get("total", 0),
        "results": [],
    }
    for hit in result.get("matches", []):
        hit_rec = {
            "ip": hit.get("ip_str"),
            "port": hit.get("port"),
            "org": hit.get("org"),
            "country": hit.get("location", {}).get("country_name"),
            "hostnames": hit.get("hostnames", [])[:5],
            "banner_snippet": (hit.get("data") or "")[:200],
            "ssl_cn": hit.get("ssl", {}).get("cert", {}).get("subject", {}).get("CN"),
        }
        if high_iocs:
            tagged = tag_banner(hit_rec, high_iocs)
            if tagged:
                hit_rec["ioc_token_hits"] = tagged
        record["results"].append(hit_rec)

    path = os.path.join(OUT_DIR, f"{query_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    print(f"    -> {record['total_shodan_index']} hosts indexed by Shodan, "
          f"{len(record['results'])} saved to {path}")
    time.sleep(RATE_LIMIT_SLEEP)
    return record


def write_summary(records):
    summary_path = os.path.join(OUT_DIR, "summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["query_id", "query", "timestamp_utc", "indexed_hosts", "saved_rows"])
        for r in records:
            w.writerow([r["query_id"], r["query"], r["timestamp_utc"],
                        r["total_shodan_index"], len(r["results"])])
    print(f"[*] Summary written to {summary_path}")


def print_top_orgs(records):
    """Tiny eye-candy stat for the weekly defense: top orgs per query."""
    for r in records:
        orgs = {}
        for hit in r["results"]:
            orgs[hit["org"] or "n/a"] = orgs.get(hit["org"] or "n/a", 0) + 1
        top = sorted(orgs.items(), key=lambda kv: -kv[1])[:3]
        if top:
            print(f"    top orgs in {r['query_id']}: " +
                  ", ".join(f"{o} ({c})" for o, c in top))


def main():
    ap = argparse.ArgumentParser(description="Shodan OSINT for exposed AD services")
    ap.add_argument("--query", help="run one custom Shodan query instead of the set")
    ap.add_argument("--self-audit", metavar="ORG_NAME",
                    help="org-scoped queries to audit your own attack surface")
    ap.add_argument("--iocs-file",
                    help="curated IoC JSON (default: references/impacket_iocs_high.json)")
    ap.add_argument("--dry-run", action="store_true", help="print queries and exit")
    ap.add_argument("--limit", type=int, default=RESULTS_PER_QUERY)
    args = ap.parse_args()

    high_iocs, ioc_src, ioc_total = load_high_iocs(args.iocs_file)
    if high_iocs:
        ntok = sum(len(i["grep_tokens"]) for i in high_iocs)
        print(f"[*] IoC hunt set: {len(high_iocs)} token-bearing IoCs "
              f"(of {ioc_total} high-relevance), {ntok} tokens <- {ioc_src}")
    else:
        print("[!] Curated IoC JSON not found - banners will NOT be IoC-tagged "
              "(copy impacket_iocs_high.json into references/)")

    if args.dry_run:
        print("[DRY RUN] Queries that would run:")
        for qid, q in QUERIES.items():
            print(f"  {qid:15s} {q}")
        if args.self_audit:
            print(f"  self-audit      org:\"{args.self_audit}\" (ports 53,88,389,445,636,3268,3269)")
        return

    if API_KEY == "PASTE-YOUR-FREE-KEY-HERE":
        sys.exit("[!] Set SHODAN_API_KEY (free key from https://shodan.io) or use --dry-run")

    if shodan is None:
        sys.exit("[!] Missing dependency: pip install shodan")

    api = shodan.Shodan(API_KEY)
    ensure_out_dir()

    records = []
    try:
        if args.self_audit:
            for port in (53, 88, 389, 445, 636, 3268, 3269):
                q = f'org:"{args.self_audit}" port:{port}'
                records.append(run_query(api, f"self_audit_{port}", q, args.limit, high_iocs))
        elif args.query:
            records.append(run_query(api, "custom_query", args.query, args.limit, high_iocs))
        else:
            for qid, q in QUERIES.items():
                records.append(run_query(api, qid, q, args.limit, high_iocs))
    except shodan.APIError as e:
        sys.exit(f"[!] Shodan API error: {e}")

    write_summary(records)
    print_top_orgs(records)
    n_tagged = sum(1 for r in records for h in r["results"] if h.get("ioc_token_hits"))
    if high_iocs:
        print(f"[*] {n_tagged} hits carried IoC token matches - check ioc_token_hits in the JSON")
    print("[+] Done. Commit the collections/ folder so the run is reproducible.")


if __name__ == "__main__":
    main()
