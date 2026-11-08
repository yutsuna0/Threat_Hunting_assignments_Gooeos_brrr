#!/usr/bin/env python3
"""
Usage
-----
    python build_navigator_layer.py                 # writes ../data/storm0501_ad_layer.json

Import: https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer
"""

import csv
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "storm0501_techniques.csv"
OUT = Path(__file__).resolve().parent.parent / "data" / "storm0501_ad_layer.json"

SCORES = {
    "AD / on-prem identity": 60,
    "Cloud pivot (Entra ID / Azure)": 40,
    "Impact / extortion & exfiltration": 80,
    "Host tradecraft": 20,
    "C2 / remote access": 10,
    "Initial access": 30,
    "Resource development": 5,
}

LEGEND = [
    {"label": "AD / on-prem identity (hunting priority)", "color": "#e74c3c"},
    {"label": "Cloud pivot (Entra ID / Azure)", "color": "#e67e22"},
    {"label": "Impact / extortion & exfiltration", "color": "#c0392b"},
    {"label": "Host tradecraft", "color": "#3498db"},
    {"label": "C2 / remote access", "color": "#95a5a6"},
    {"label": "Initial access", "color": "#f1c40f"},
    {"label": "Resource development", "color": "#bdc3c7"},
]


def build_layer(techniques):
    entries = []
    for t in techniques:
        score = SCORES.get(t["category"], 0)
        comment = t["use_note"]
        if t["tool_context"]:
            comment += f" (tools: {t['tool_context']})"
        entry = {
            "techniqueID": t["technique_id"],
            "score": score,
            "enabled": True,
            "comment": comment,
            "showSubtechniques": True,
        }
        entries.append(entry)

    ad_count = sum(1 for t in techniques if t["category"].startswith("AD"))
    cloud_count = sum(1 for t in techniques if t["category"] == "Cloud pivot (Entra ID / Azure)")

    return {
        "name": "Storm-0501 (G1053) - AD Attack Chain (Week 10 hunt scope)",
        "version": "4.5",
        "domain": "enterprise",
        "description": (
            "Enterprise techniques used by Storm-0501 (G1053), annotated for the group topic "
            "'Threat Hunting for Active Directory Attacks'. Scores encode the role of each "
            f"technique in the AD-to-cloud attack chain: {ad_count} on-prem AD techniques, "
            f"{cloud_count} cloud-pivot techniques. Built from the official MITRE layer "
            "(v1.0) - see data/storm0501_techniques.csv."
        ),
        "filters": {"platforms": ["Windows", "IaaS", "Azure AD"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True,
                   "showName": True, "showAggregateScores": False, "countUnscored": False},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {
            "colors": ["#bdc3c7", "#f1c40f", "#e67e22", "#c0392b"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": LEGEND,
        "metadata": [
            {"name": "Course", "value": "Introduction to Threat Hunting - Astana IT University"},
            {"name": "Group topic", "value": "Threat Hunting for Active Directory Attacks"},
            {"name": "Week", "value": "10 - Learning APT Techniques"},
            {"name": "Sources", "value": "attack.mitre.org/groups/G1053; Microsoft Threat Intelligence "
                                         "blog 2024-09-26 and 2025-08-27; Avertium (2022); "
                                         "McLellan & Schondorfer 'Kitten.gif' (2021)"},
        ],
        "links": [
            {"label": "MITRE G1053", "url": "https://attack.mitre.org/groups/G1053/"},
            {"label": "Microsoft blog (Aug 2025)", "url": "https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware"},
        ],
    }


def main():
    with open(DATA, encoding="utf-8") as fh:
        techniques = list(csv.DictReader(fh))
    layer = build_layer(techniques)
    OUT.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    counts = {}
    for t in techniques:
        counts[t["category"]] = counts.get(t["category"], 0) + 1
    print(f"Layer written: {OUT}")
    print(f"Techniques annotated: {len(techniques)}")
    for cat, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {SCORES.get(cat, 0):>3} pts  {cat:<38} x{count}")


if __name__ == "__main__":
    main()
