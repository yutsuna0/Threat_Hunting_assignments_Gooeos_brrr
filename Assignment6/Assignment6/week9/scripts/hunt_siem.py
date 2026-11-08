#!/usr/bin/env python3
"""
Usage
-----
    python hunt_siem.py --input ../data/sysmon_parsed.csv --outdir ../output
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Detection rules. "all" = every condition must match, "any" = one is enough.
# Rule IDs are referenced from the atomic test plan (hunt_rule_id column).
# --------------------------------------------------------------------------
RULES = [
    {
        "id": "R-101",
        "technique": "T1059.001",
        "name": "Suspicious PowerShell execution",
        "tactic": "Execution",
        "event_ids": ["1"],
        "mode": "all",
        "enabled": True,
        "conditions": [
            {"field": "Image", "pattern": r"(?i)powershell(\.exe)?$"},
            {"field": "CommandLine", "pattern": r"(?i)(-enc|encodedcommand|-w\s+hidden|-windowstyle\s+hidden|-nop|-noni|iex|invoke-expression|downloadstring)"},
        ],
        "description": "PowerShell launched with encoded/hidden/non-interactive flags or download cradles.",
    },
    {
        "id": "R-102",
        "technique": "T1558.003",
        "name": "Kerberoasting service ticket request",
        "tactic": "Credential Access",
        "event_ids": ["1"],
        "mode": "any",
        "enabled": True,
        "conditions": [
            {"field": "CommandLine", "pattern": r"(?i)kerberosrequestorsecuritytoken"},
            {"field": "CommandLine", "pattern": r"(?i)(invoke-)?kerberoast"},
            {"field": "Image", "pattern": r"(?i)\\rubeus(\.exe)?$"},
        ],
        "description": "KerberosRequestorSecurityToken requests, PowerView/Rubeus kerberoast tooling.",
    },
    {
        "id": "R-103",
        "technique": "T1003.006",
        "name": "DCSync replication abuse",
        "tactic": "Credential Access",
        "event_ids": ["1"],
        "mode": "any",
        "enabled": True,
        "conditions": [
            {"field": "CommandLine", "pattern": r"(?i)dcsync"},
            {"field": "CommandLine", "pattern": r"(?i)secretsdump"},
            {"field": "CommandLine", "pattern": r"(?i)lsadump::dcsync"},
            {"field": "CommandLine", "pattern": r"(?i)-just-dc"},
        ],
        "description": "Impacket secretsdump / Mimikatz lsadump arguments requesting replication of hash data.",
    },
    {
        "id": "R-104",
        "technique": "T1136.002",
        "name": "Domain account created via net.exe",
        "tactic": "Persistence",
        "event_ids": ["1"],
        "mode": "all",
        "enabled": True,
        "conditions": [
            {"field": "Image", "pattern": r"(?i)\\net\.exe$"},
            {"field": "CommandLine", "pattern": r"(?i)user\s+\S+\s+\S+\s+/add"},
            {"field": "CommandLine", "pattern": r"(?i)/domain"},
        ],
        "description": "net.exe adding a user with the /domain flag (directory-level account creation).",
    },
    {
        "id": "R-105",
        "technique": "T1021.006",
        "name": "Remote execution over WinRM",
        "tactic": "Lateral Movement",
        "event_ids": ["1"],
        "mode": "any",
        "enabled": True,
        "conditions": [
            {"field": "Image", "pattern": r"(?i)\\winrs(\.exe)?$"},
            {"field": "Image", "pattern": r"(?i)evil-winrm"},
            {"field": "CommandLine", "pattern": r"(?i)winrs(\.exe)?\s+-r:"},
        ],
        "description": "winrs.exe / Evil-WinRM remote PowerShell sessions to another host.",
    },
    {
        "id": "R-106",
        "technique": "T1087.002",
        "name": "AD reconnaissance tooling (demo rule)",
        "tactic": "Discovery",
        "event_ids": ["1"],
        "mode": "any",
        "enabled": False,  # kept disabled: no week-9 atomic maps to it yet (Week 10 backlog)
        "conditions": [
            {"field": "CommandLine", "pattern": r"(?i)(adrecon|adfind|sharpview|nltest)"},
        ],
        "description": "Example extension rule showing how new hunts are added; disabled in this run.",
    },
]

SOFTWARE_ASSOCIATIONS = {
    # technique -> observed Storm-0501 / lab tooling that also triggers the rule
    "T1558.003": "Rubeus / PowerView / .NET KerberosRequestorSecurityToken",
    "T1003.006": "Impacket secretsdump.py / Mimikatz lsadump::dcsync",
    "T1136.002": "net.exe (native)",
    "T1021.006": "winrs.exe / Evil-WinRM",
    "T1059.001": "powershell.exe (native)",
}


def compile_rules():
    """Attach compiled regexes to every enabled rule."""
    for rule in RULES:
        for cond in rule["conditions"]:
            cond["regex"] = re.compile(cond["pattern"])
    return RULES


def rule_matches(rule, record):
    """Evaluate one rule against one parsed Sysmon record."""
    if record["EventID"] not in rule["event_ids"]:
        return None
    hits = []
    for cond in rule["conditions"]:
        value = record.get(cond["field"], "") or ""
        match = cond["regex"].search(value)
        if match:
            hits.append((cond["field"], match.group(0)))
    if rule["mode"] == "all":
        matched = len(hits) == len(rule["conditions"])
    else:
        matched = len(hits) > 0
    return hits if matched else None


def hunt(records, rules):
    """Run all rules over all records. Returns alerts and per-rule stats."""
    alerts = []
    stats = defaultdict(lambda: {"count": 0, "first": "", "last": "", "hosts": set(), "users": set()})
    for record in records:
        for rule in rules:
            if not rule["enabled"]:
                continue
            hits = rule_matches(rule, record)
            if hits:
                alerts.append({
                    "AlertTime": record["EventTime"],
                    "RuleID": rule["id"],
                    "Technique": rule["technique"],
                    "RuleName": rule["name"],
                    "Tactic": rule["tactic"],
                    "Computer": record["Computer"],
                    "User": record["User"],
                    "Image": record["Image"],
                    "CommandLine": record["CommandLine"],
                    "MatchedOn": "; ".join(f"{field}~'{text}'" for field, text in hits),
                })
                entry = stats[rule["id"]]
                entry["count"] += 1
                entry["first"] = entry["first"] or record["EventTime"]
                entry["last"] = record["EventTime"]
                entry["hosts"].add(record["Computer"])
                entry["users"].add(record["User"])
    return alerts, stats


def write_outputs(alerts, stats, records, outdir, plan_path):
    outdir.mkdir(parents=True, exist_ok=True)

    # alerts.csv
    alert_fields = ["AlertTime", "RuleID", "Technique", "RuleName", "Tactic",
                    "Computer", "User", "Image", "CommandLine", "MatchedOn"]
    with open(outdir / "alerts.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=alert_fields)
        writer.writeheader()
        writer.writerows(alerts)

    # stats.json
    stats_json = {
        rule["id"]: {
            "technique": rule["technique"],
            "name": rule["name"],
            "count": stats[rule["id"]]["count"],
            "first_seen": stats[rule["id"]]["first"],
            "last_seen": stats[rule["id"]]["last"],
            "hosts": sorted(stats[rule["id"]]["hosts"]),
            "users": sorted(stats[rule["id"]]["users"]),
        }
        for rule in RULES if rule["enabled"]
    }
    payload = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "events_ingested": len(records),
        "alerts_total": len(alerts),
        "rules": stats_json,
    }
    (outdir / "stats.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # hunt_report.md
    times = sorted(r["EventTime"] for r in records if r["EventTime"])
    lines = [
        "# Week 9 Hunt Report",
        "",
        f"Generated: {payload['generated']}",
        "",
        "## Dataset",
        f"- Events ingested: **{len(records)}**",
        f"- Time range: `{times[0]}` to `{times[-1]}`" if times else "- (empty dataset)",
        f"- Alerts raised: **{len(alerts)}**",
        "",
        "## Rule Results",
        "",
        "| Rule | Technique | Detection | Alerts | First seen | Last seen |",
        "|---|---|---|---:|---|---|",
    ]
    for rule in RULES:
        if not rule["enabled"]:
            lines.append(f"| {rule['id']} | {rule['technique']} | {rule['name']} | disabled | - | - |")
            continue
        entry = stats_json[rule["id"]]
        lines.append(
            f"| {rule['id']} | {rule['technique']} | {rule['name']} "
            f"| {entry['count']} | {entry['first_seen'][:19] or '-'} | {entry['last_seen'][:19] or '-'} |"
        )
    lines += ["", "## Test Plan Coverage", ""]
    with open(plan_path, encoding="utf-8") as fh:
        plan = list(csv.DictReader(fh))
    lines += ["| Test | Technique | Atomic test | Rule | Verdict |", "|---|---|---|---|---|"]
    for t in plan:
        entry = stats_json.get(t["hunt_rule_id"])
        count = entry["count"] if entry else 0
        verdict = "DETECTED" if count else "not detected"
        lines.append(f"| {t['test_id']} | {t['technique_id']} | {t['test_name']} | {t['hunt_rule_id']} | {verdict} ({count}) |")
    lines += ["", "## Sample Alerts", ""]
    shown = defaultdict(int)
    for alert in alerts:
        if shown[alert["RuleID"]] >= 2:
            continue
        shown[alert["RuleID"]] += 1
        lines += [
            f"### {alert['RuleID']} - {alert['RuleName']} ({alert['Technique']})",
            f"- Time: {alert['AlertTime']}",
            f"- Host/User: {alert['Computer']} / {alert['User'] or 'n/a'}",
            f"- Image: `{alert['Image']}`",
            f"- CommandLine: `{alert['CommandLine']}`",
            "",
        ]
    (outdir / "hunt_report.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def main():
    parser = argparse.ArgumentParser(description="Python mini-SIEM for the Week 9 AD hunt.")
    parser.add_argument("--input", type=Path, required=True, help="sysmon_parsed.csv")
    parser.add_argument("--outdir", type=Path, default=Path(__file__).resolve().parent.parent / "output")
    parser.add_argument("--plan", type=Path,
                        default=Path(__file__).resolve().parent.parent / "data" / "atomic_test_plan.csv")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        records = list(csv.DictReader(fh))

    rules = compile_rules()
    alerts, stats = hunt(records, rules)
    payload = write_outputs(alerts, stats, records, args.outdir, args.plan)

    print(f"Events ingested: {payload['events_ingested']}")
    print(f"Alerts total   : {payload['alerts_total']}")
    for rule_id, entry in payload["rules"].items():
        print(f"  {rule_id} {entry['technique']} {entry['name']:<38} -> {entry['count']} alert(s)")
    print(f"Outputs in {args.outdir}: alerts.csv, stats.json, hunt_report.md")


if __name__ == "__main__":
    main()
