import csv
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

INPUT_FILE = BASE_DIR / "data" / "master_ioc_collection.csv"
OUTPUT_FILE = BASE_DIR / "data" / "normalized_dataset.csv"
MISP_FILE = BASE_DIR / "data" / "misp_sha256.txt"

normalized = []
hashes = set()
seen = set()

total = 0
removed = 0

with INPUT_FILE.open("r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)
    fieldnames = reader.fieldnames + ["indicator_type"]

    for row in reader:
        total += 1

        # Normalize whitespace
        cleaned = {
            key: (row.get(key) or "").strip()
            for key in reader.fieldnames
        }

        cleaned["severity"] = cleaned["severity"].lower()

        source = cleaned["source"].lower()
        identifier = cleaned["identifier"]

        # Filter empty records
        if not source or not identifier:
            removed += 1
            continue

        # Classify indicators
        if source == "virustotal":
            identifier = identifier.lower()
            cleaned["identifier"] = identifier

            if re.fullmatch(r"[0-9a-f]{64}", identifier):
                cleaned["indicator_type"] = "sha256"
                hashes.add(identifier)
            else:
                cleaned["indicator_type"] = "invalid_hash"

        elif source == "shodan":
            cleaned["indicator_type"] = "infrastructure_query"

        elif source == "impacket-iocs":
            cleaned["indicator_type"] = "behavioral_indicator"

        else:
            cleaned["indicator_type"] = "unknown"

        # Remove duplicate records
        key = (
            source,
            cleaned["identifier"],
            cleaned["title_or_query"]
        )

        if key in seen:
            removed += 1
            continue

        seen.add(key)
        normalized.append(cleaned)

# Save normalized dataset
with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(normalized)

# Prepare SHA256 indicators for MISP
with MISP_FILE.open("w", encoding="utf-8") as file:
    for hash_value in sorted(hashes):
        file.write(hash_value + "\n")

print(f"Records processed: {total}")
print(f"Records removed: {removed}")
print(f"Normalized records: {len(normalized)}")
print(f"SHA256 indicators prepared for MISP: {len(hashes)}")
print("Processing completed successfully.")
