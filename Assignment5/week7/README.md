
# Week 7 — MITRE CAR Detection in Splunk

## Objective
Select an analytic from MITRE CAR, implement it in a SIEM, and map the results to MITRE ATT&CK.

## Selected Analytic
- **CAR ID:** CAR-2013-08-001
- **Name:** Execution with schtasks
- **Platform:** Windows
- **SIEM:** Splunk Enterprise 9.4.2
- **Data source:** Sysmon Event ID 1 (Process Creation)

The analytic detects executions of schtasks.exe, which attackers may abuse to establish persistence through scheduled tasks.

## Analytics vs. Detections
An analytic describes the logic for recognizing potentially malicious behavior. A detection is its implementation using a specific SIEM query and data source.

Our implementation uses the SPL query in `detection.spl`.

## Dataset and Processing
Source: [Splunk Attack Data](https://github.com/splunk/attack_data)

We used authentic Sysmon logs from a previously recorded attack simulation, not a live attack on our device.

The Python script `parse_sysmon.py` converts the raw XML data into structured CSV format.

| Metric | Result |
|---|---:|
| Total events | 410 |
| Parsing errors | 0 |
| Process Creation events | 16 |
| CAR matches | 2 |

The processed dataset is stored in `sysmon_parsed.csv`.

## SIEM Implementation
The parsed CSV was imported into Splunk.

The detection searches for process creation events where the executable is `schtasks.exe`.

The query also identifies task creation commands and adds MITRE ATT&CK metadata.

## Detection Results
Two scheduled task creation commands were identified:

1. **SoundIentifier:** A scheduled task invoking WMIC and referencing a file in a public directory.
2. **Disk Diag:** A recurring scheduled task invoking explorer.exe with a JavaScript file.

Both match the selected CAR analytic.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Persistence (TA0003) |
| Technique | Scheduled Task/Job (T1053) |
| Sub-technique | Scheduled Task (T1053.005) |
| CAR | CAR-2013-08-001 |

### Event Distribution Analysis

The dataset contains 410 Sysmon events across six event types:

| Event ID | Description | Count |
|---|---|---:|
| 10 | Process Access | 179 |
| 23 | File Delete | 161 |
| 3 | Network Connection | 42 |
| 1 | Process Creation | 16 |
| 13 | Registry Value Set | 10 |
| 11 | File Create | 2 |

The CAR analytic focuses on process creation events (Event ID 1).

Out of 16 process creation events, two schtasks.exe executions were identified.

These events represent 12.5% of process creation events and approximately 0.49% of the complete dataset.

The two matching commands create scheduled tasks named SoundIentifier and Disk Diag. Both require further investigation to determine whether they represent malicious activity.

## Limitations
- Legitimate administrators also use schtasks.exe.
- A match does not automatically confirm malicious activity.
- The detection does not cover every method of scheduled task creation.
- Historical attack data was used instead of live monitoring.

## Conclusion
The MITRE CAR analytic was successfully implemented in Splunk.

The parser processed 410 Sysmon events without errors, and the detection identified two executions of schtasks.exe associated with T1053.005.

## References
- https://car.mitre.org/analytics/CAR-2013-08-001/
- https://attack.mitre.org/techniques/T1053/005/
- https://github.com/splunk/attack_data


ChatGPT assisted . 

