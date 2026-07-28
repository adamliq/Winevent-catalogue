# Winevent-catalogue

A structured catalogue of Windows Event Log IDs. Built from a personal MS
Server administration notebook (TiddlyWiki export) covering Security
auditing events (mapped to their Group Policy audit subcategories), DHCP
Server events, Removable Media / Plug-and-Play device events, Network
Location Awareness (NLA) events, Terminal Services / RDS session events,
and System shutdown/restart events — plus WebAuthn (FIDO2/Windows Hello)
operational log events (sourced from the real Microsoft-Windows-WebAuthN
ETW manifest) and event IDs cross-referenced from the ASD/ACSC "Priority
logs for SIEM ingestion: Practitioner guidance" (2025), including AD FS,
LDAP signing, Code Integrity/WDAC, AppLocker, Sysmon, PowerShell, WMI
Activity, Task Scheduler, ESENT, and Windows DNS Server analytic events.

## Contents

- `data/events.csv` / `data/events.json` — the main catalogue, one row per
  `(event_id, log, category, subcategory)` combination:
  - `event_id` — the Windows Event ID (decimal, or hex where the source used hex)
  - `log` — the event log / channel the event is written to
  - `source` — the event provider / source name
  - `category` — high-level grouping (e.g. `DHCP`, `Removable Media / Device (PNP)`,
    or the Group Policy "Audit ..." category for Security events)
  - `subcategory` — the specific Group Policy audit subcategory, where applicable
  - `description` — what the event means
  - `sample` — every event has one: a real sample where the source notebook
    captured one, otherwise a generated representative example (Event
    Viewer-style text) using a consistent fictional environment
    (`CORP.LOCAL` domain, `DC01.corp.local`, etc.)
  - `reference` — pointer to related configuration notes or docs
  - `how_to_collect` — which auditing subcategory/subcategories (from
    `data/reference/audit_configuration.csv`) must be enabled to generate
    this event
  - `sample_type` — `original` (captured from the source notebook) or
    `illustrative` (generated); the web lookup page tags illustrative
    samples so they're never mistaken for a real capture
  - `mitre_techniques` — MITRE ATT&CK technique ID(s) associated with the
    event, where mapped (populated for Sysmon, AppLocker, Code Integrity,
    Windows Defender, and related detection-relevant events; blank
    elsewhere)

- `data/reference/audit_configuration.csv` / `.json` — how to configure
  auditing to collect events, one row per audit subcategory (or
  product-specific setting): the Group Policy / registry path, the steps to
  enable it, the event IDs it produces, and a reference URL where available.
  See `docs/audit-configuration-guide.md` for the readable version.
- `data/reference/audit_policy_matrix.csv` — the raw Group Policy audit
  category → Event ID mapping (Account Logon, Account Management, Detailed
  Tracking, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege
  Use, System, Global Object Access Auditing), before expansion into
  `events.csv`.
- `data/reference/ntlm_error_codes_4776.csv` — NTLM/Kerberos status codes
  seen in the `Error Code` field of Event ID 4776.
- `data/reference/disconnect_reason_codes_event40.csv` — RDS client
  disconnect reason codes seen in Event ID 40
  (`TerminalServices-LocalSessionManager`).
- `data/reference/sharepoint_audit_event_types.csv` — SharePoint audit log
  event type codes. These use a separate numbering scheme from Windows
  Event Log IDs and are kept out of the main catalogue to avoid collisions.
- `docs/event-log-operations.md` — PowerShell / `wevtutil` snippets for
  querying, exporting, and clearing event logs, including a working example
  for auditing user account creation (Event ID 4720) across all domain
  controllers.
- `docs/audit-configuration-guide.md` — how to configure Windows/AD to
  actually collect each event: the Advanced Audit Policy Configuration (or
  registry) path to enable, step-by-step instructions, and the event IDs
  each setting produces.

## Web lookup

`site/index.html` is a self-contained (no build step, no external requests)
lookup page: search all 742 events by ID or keyword, filter by log/category,
and view full detail — description, sample log text, and how-to-collect
configuration steps — plus a reference-tables tab for the NTLM/disconnect
code lookups and the raw audit policy matrix. Open it directly in a browser.

## Source

Extracted from a TiddlyWiki 5 export ("MSServer" notebook) covering Windows
Server administration topics. Only the Event Log / Event ID related tiddlers
were used to build this catalogue.

WebAuthn events were cross-checked against the real
`Microsoft-Windows-WebAuthN` ETW provider manifest (event IDs, symbols, and
field names verified, not guessed). Events added from the ASD/ACSC SIEM
ingestion guidance carry that document's exact category/event-ID pairings;
a handful of low-confidence entries (exact log channel not independently
corroborated — e.g. the two "Kerberos" events 4678/4679, and the log
channel split for 3033/3063) say so explicitly in their `reference` field.

Also cross-referenced against Microsoft's "Appendix L: Events to Monitor"
(fetched from the public `MicrosoftDocs/windowsserverdocs` GitHub mirror)
and Graylog's "Critical Windows Event IDs to Monitor" — both were almost
entirely already covered (both draw on the same underlying "Monitoring
Active Directory for Signs of Compromise" reference as the ASD guidance);
the genuinely new additions were IPsec/OCSP Responder Service Security-log
events, Netlogon secure-channel hardening events (Zerologon, CVE-2020-1472),
the classic "previous shutdown was unexpected" event, BitLocker volume
encryption/decryption/conversion events, and a Windows Time Service event
relevant to detecting clock-manipulation attacks.

Also cross-referenced against an uploaded "Windows Event ID Catalogue"
reference spreadsheet (provider/channel/event ID/description/level/MITRE
ATT&CK technique/collection-priority schema). ~40% of its 339 rows were
already covered; the rest — full Sysmon event ID coverage (1-29), Windows
Defender/Operational events, further AppLocker/Code Integrity/DNS-Client/
PowerShell/Task Scheduler events, Windows Update and Service Control
Manager System-log events, and a handful of same-numbered-but-different-
channel events (e.g. Sysmon's own 21-25 vs. Terminal Services' 21-25) —
were added, carrying that source's MITRE ATT&CK mappings where provided.
