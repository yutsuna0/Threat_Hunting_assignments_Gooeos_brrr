# Week 3 — Data Processing and Exploitation

## 1. Project Topic

Threat Hunting for Active Directory Attacks

## 2. Objective

The objective of Week 3 was to process the threat intelligence data collected during Week 2, apply filtering and normalization techniques, and import selected Indicators of Compromise (IOCs) into MISP.

## 3. Data Collection Results

The input dataset was collected during Week 2 and stored in master_ioc_collection.csv.

The dataset contains 69 records from three sources:

| Source | Records | Description |
|--------|---------|-------------|
| Shodan | 5 | Infrastructure exposure queries |
| VirusTotal | 41 | SHA256 hashes and tool reputation information |
| Impacket-IoCs | 23 | Behavioral indicators related to Active Directory attacks |

The dataset also includes MITRE ATT&CK technique identifiers, attack stages, severity levels, and additional information where available.

## 4. Data Filtering and Normalization

A Python script was developed to process the collected dataset.

The script performs the following operations:

- Removes unnecessary whitespace.
- Checks for duplicate and empty records.
- Standardizes severity values.
- Validates SHA256 hash formats.
- Classifies indicators according to their source and type.

The processing results were:

| Metric | Result |
|--------|--------|
| Total records processed | 69 |
| Records removed | 0 |
| Normalized records | 69 |
| SHA256 indicators prepared for MISP | 41 |

All 69 records were preserved in the normalized dataset.

The Shodan queries and Impacket behavioral indicators were not imported as SHA256 attributes because they represent different types of threat intelligence.

## 5. MISP Deployment

MISP was deployed locally using Docker Desktop.

The deployment includes the MISP application, database, Redis, MISP Modules, and the web server.

After the containers were initialized, the MISP web interface was accessed through the local browser.

A new event was created with the following configuration:

Event: Week 3 - AD Threat Hunting - Tool Hash Collection

Event ID: 1

Distribution: Your organisation only

Analysis: Initial

## 6. IOC Import

The 41 SHA256 hashes were extracted from the normalized dataset and saved in misp_sha256.txt.

The hashes were imported into MISP using the Freetext Import function.

MISP successfully recognized and imported all 41 SHA256 attributes.

The event contains 41 attributes and remains unpublished.

The imported hashes are collected threat intelligence indicators. Their presence in VirusTotal does not independently prove that every associated file is malicious.

## 7. Data Enrichment and Correlation

The normalized dataset preserves the original source information and relevant MITRE ATT&CK identifiers.

Automated enrichment and correlation were not performed during this increment.

These activities can be explored in future project stages.

## 8. Project Files

- data/master_ioc_collection.csv — original Week 2 dataset.
- data/normalized_dataset.csv — normalized dataset.
- data/misp_sha256.txt — SHA256 indicators prepared for MISP.
- scripts/normalize_iocs.py — Python processing script.

## 9. Reproduction

To reproduce the data processing step, run:

    python3 week3/scripts/normalize_iocs.py

The script generates the normalized dataset and the SHA256 indicator list.

MISP was deployed separately using the official misp-docker project.

## 10. Conclusion

During Week 3, the collected threat intelligence data was processed and normalized using Python.

A total of 69 records were processed, and 41 SHA256 indicators were prepared and imported into MISP.

The resulting dataset and MISP event provide a structured foundation for further threat hunting activities.
