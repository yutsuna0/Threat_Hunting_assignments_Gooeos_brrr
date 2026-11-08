#!/usr/bin/env python3
"""
Usage
-----
    python parse_sysmon.py sysmon_export.xml sysmon_parsed.csv
"""

import csv
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDS = [
    "EventTime", "EventID", "Computer", "User",
    "Image", "CommandLine", "ParentImage", "ParentCommandLine",
    "ProcessId", "ProcessGuid", "Hashes", "DestinationIp", "DestinationHostname",
]

EVENT_SPLIT = re.compile(r"<Event\b", re.IGNORECASE)


def iter_events(raw_text):
    """Yield <Event> XML fragments from either single-line or multi-line files."""
    if "<Event " in raw_text[:2000] or "<Event>" in raw_text[:2000]:
        # Multi-line export: split on the <Event tag.
        parts = EVENT_SPLIT.split(raw_text)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if not part.endswith(">"):
                idx = part.rfind("</Event>")
                part = part[: idx + len("</Event>")] if idx >= 0 else part
            yield "<Event " + part if not part.startswith("<Event") else part
    else:
        for line in raw_text.splitlines():
            if line.strip():
                yield line.strip()


def parse_fragment(fragment):
    """Parse one <Event> fragment into a flat record (or None on error)."""
    try:
        root = ET.fromstring(fragment)
    except ET.ParseError:
        return None

    system = root.find("e:System", NS)
    if system is None:
        return None

    event_data = {
        item.get("Name"): (item.text or "")
        for item in root.findall("e:EventData/e:Data", NS)
    }

    time_node = system.find("e:TimeCreated", NS)
    record = {
        "EventTime": time_node.get("SystemTime", "") if time_node is not None else "",
        "EventID": system.findtext("e:EventID", default="", namespaces=NS),
        "Computer": system.findtext("e:Computer", default="", namespaces=NS),
        "User": event_data.get("User", ""),
        "Image": event_data.get("Image", ""),
        "CommandLine": event_data.get("CommandLine", ""),
        "ParentImage": event_data.get("ParentImage", ""),
        "ParentCommandLine": event_data.get("ParentCommandLine", ""),
        "ProcessId": event_data.get("ProcessId", ""),
        "ProcessGuid": event_data.get("ProcessGuid", "{00000000-0000-0000-0000-000000000000}"),
        "Hashes": event_data.get("Hashes", ""),
        "DestinationIp": event_data.get("DestinationIp", ""),
        "DestinationHostname": event_data.get("DestinationHostname", ""),
    }
    return record


def parse_log(source, destination):
    raw = Path(source).read_text(encoding="utf-8-sig", errors="replace")
    records, errors = [], 0

    for fragment in iter_events(raw):
        record = parse_fragment(fragment)
        if record is None:
            errors += 1
        else:
            records.append(record)

    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"Parsed events: {len(records)}")
    print(f"Parsing errors: {errors}")
    print(f"Output: {destination}")

    by_id = {}
    for record in records:
        by_id[record["EventID"]] = by_id.get(record["EventID"], 0) + 1
    for event_id in sorted(by_id, key=lambda x: -by_id[x]):
        print(f"  Event ID {event_id}: {by_id[event_id]}")

    process_events = by_id.get("1", 0)
    print(f"Process Creation events (ID 1): {process_events}")
    return records


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parse_sysmon.py input.xml output.csv")
        sys.exit(1)
    parse_log(sys.argv[1], sys.argv[2])
