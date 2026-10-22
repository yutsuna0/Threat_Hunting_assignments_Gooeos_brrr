
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDS = [
    "EventTime", "EventID", "Computer", "User",
    "Image", "CommandLine", "ParentImage",
    "ProcessId", "ProcessGuid"
]

def parse_log(source, destination):
    records = []
    errors = 0

    with open(source, "r", encoding="utf-8-sig") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                root = ET.fromstring(line.strip())
            except ET.ParseError:
                errors += 1
                continue

            system = root.find("e:System", NS)
            if system is None:
                errors += 1
                continue

            event_data = {
                item.get("Name"): item.text or ""
                for item in root.findall("e:EventData/e:Data", NS)
            }

            event_id = system.findtext("e:EventID", default="", namespaces=NS)
            computer = system.findtext("e:Computer", default="", namespaces=NS)

            time_node = system.find("e:TimeCreated", NS)
            event_time = (
                time_node.get("SystemTime", "")
                if time_node is not None else ""
            )

            record = {
                "EventTime": event_time,
                "EventID": event_id,
                "Computer": computer,
                "User": event_data.get("User", ""),
                "Image": event_data.get("Image", ""),
                "CommandLine": event_data.get("CommandLine", ""),
                "ParentImage": event_data.get("ParentImage", ""),
                "ProcessId": event_data.get("ProcessId", ""),
                "ProcessGuid": event_data.get("ProcessGuid", "")
            }

            records.append(record)

    with open(destination, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"Parsed events: {len(records)}")
    print(f"Parsing errors: {errors}")
    print(f"Output: {destination}")

    process_events = sum(
        1 for record in records if record["EventID"] == "1"
    )
    print(f"Process Creation events (ID 1): {process_events}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 parse_sysmon.py input.log output.csv")
        sys.exit(1)

    parse_log(Path(sys.argv[1]), Path(sys.argv[2]))

