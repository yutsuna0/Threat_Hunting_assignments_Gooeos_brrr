# Week 2 — OSINT Collection Scripts

## `shodan_hunt.py`
Runs a fixed set of Shodan queries targeting internet-exposed Active Directory
services (LDAP, Global Catalog, Kerberos, SMB). Saves each result set as JSON
with full provenance (query, timestamp, source), plus a summary CSV. Also
cross-references result banners against our curated Impacket IOC tokens to
flag any infrastructure matches.

## `vt_lookup.py`
Takes a list of SHA-256 hashes (collected from AD attack tools such as
Mimikatz, Rubeus, and SharpCollection binaries) and queries the VirusTotal
API for detection ratio, known file names, and tags. Saves one JSON report
per hash for traceability.

## A Note on Methodology
Both scripts were, in the finest modern tradition, vibecoded :D
