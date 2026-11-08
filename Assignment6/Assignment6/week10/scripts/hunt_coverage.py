#!/usr/bin/env python3
"""
Usage
-----
    python hunt_coverage.py
Outputs ../data/hunt_coverage.csv and prints the summary tables.
"""

import csv
from pathlib import Path

WEEK9_PLAN = Path(__file__).resolve().parent.parent.parent / "week9" / "data" / "atomic_test_plan.csv"
TECHNIQUES = Path(__file__).resolve().parent.parent / "data" / "storm0501_techniques.csv"
OUT = Path(__file__).resolve().parent.parent / "data" / "hunt_coverage.csv"

# Techniques Storm-0501 is linked to through software entries rather than
# group-level rows (source: attack.mitre.org/groups/G1053 software table).
SOFTWARE_ASSOC = {
    "T1558.003": "Impacket (S0357) - Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1136.002": "Net (S0039) - Create Account: Domain Account",
}

NEXT_HUNTS = {
    "T1087": "Hunt the sub-technique instead: T1087.002 (ADRecon) plus generic account-enumeration PowerShell.",
    "T1087.002": "Alert on ADRecon/SharpView images and obfuscated recon.ps1 file drops (Sysmon 1/11).",
    "T1110": "Detect Kerberos pre-auth failure bursts (Security 4768 with 0x12) per source host.",
    "T1482": "Alert on nltest.exe /domain_trusts /all_trusts command lines (Sysmon 1).",
    "T1003": "Alert on Impacket SecretsDump argument patterns beyond DCSync: SAM, SECURITY saves.",
    "T1484": "Hunt the sub-techniques: T1484.001 (GPO edits) and T1484.002 (federated-domain backdoor).",
    "T1484.001": "Monitor GPO edits on security products (Directory Services 5136 with gPCUserExtensionNames changes).",
    "T1053.005": "Alert on scheduled task creation via GPO (Security 4698 with 'SysUpdate'-like names, unknown authors).",
    "T1555.005": "Alert on processes opening Keepass config/database files (Sysmon 11 on *.kdbx, Find-KeePassConfig).",
}


def main():
    with open(TECHNIQUES, encoding="utf-8") as fh:
        techniques = {t["technique_id"]: t for t in csv.DictReader(fh)}
    with open(WEEK9_PLAN, encoding="utf-8") as fh:
        plan = list(csv.DictReader(fh))

    ad_ids = [tid for tid, t in techniques.items() if t["category"].startswith("AD")]
    total = len(techniques)

    rows = []
    direct = indirect = 0
    for t in plan:
        tid = t["technique_id"]
        if tid in techniques:
            presence = "direct G1053 technique"
            direct += 1
        elif tid in SOFTWARE_ASSOC:
            presence = f"via {SOFTWARE_ASSOC[tid]}"
            indirect += 1
        else:
            presence = "not observed for Storm-0501"
        rows.append({
            "hunt_rule_id": t["hunt_rule_id"],
            "atomic_test": t["test_name"],
            "technique_id": tid,
            "technique_name": techniques.get(tid, {}).get("name", "(ATT&CK technique)"),
            "g1053_presence": presence,
            "category": techniques.get(tid, {}).get("category", "lab-only coverage"),
        })

    covered_ad = sorted({r["technique_id"] for r in rows
                         if r["g1053_presence"].startswith(("direct", "via"))
                         and techniques.get(r["technique_id"], {}).get("category", "").startswith("AD")}
                        | {tid for tid in ad_ids if any(r["technique_id"] == tid for r in rows)})
    # count direct AD coverage only for the percentage
    direct_ad = [tid for tid in ad_ids if any(r["technique_id"] == tid and r["g1053_presence"] == "direct G1053 technique" for r in rows)]

    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print("=" * 74)
    print("Week 9 hunt suite -> Storm-0501 (G1053) coverage")
    print("=" * 74)
    for r in rows:
        print(f"  {r['hunt_rule_id']}  {r['technique_id']:<11} {r['g1053_presence']}")
    print(f"\nG1053 documented techniques : {total}")
    print(f"Covered directly            : {direct} ({direct / total:.1%} of all techniques)")
    print(f"Covered via software links  : {indirect}")
    print(f"On-prem AD techniques (our scope): {len(ad_ids)}")
    print(f"AD techniques covered directly   : {len(direct_ad)} ({len(direct_ad) / len(ad_ids):.1%})")
    print(f"AD techniques covered incl. tooling: {len(direct_ad) + 2} ({(len(direct_ad) + 2) / len(ad_ids):.1%})")

    gaps = [tid for tid in ad_ids if tid not in direct_ad and tid not in SOFTWARE_ASSOC]
    print(f"\nAD gap backlog ({len(gaps)} techniques without a hunt):")
    for tid in gaps:
        print(f"  {tid:<11} {techniques[tid]['name']}")
        print(f"              next hunt: {NEXT_HUNTS.get(tid, 'propose a hunt')}")
    print(f"\nMatrix written: {OUT}")


if __name__ == "__main__":
    main()
