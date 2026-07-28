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
  - `sample_type` — `original` (captured from the source notebook),
    `illustrative` (a representative example I built), or `template` (the
    event's raw message string as published in the source ETW manifest,
    with its `{Placeholder}` tokens left unfilled — used for the bulk ETW
    manifest import, see below). The web lookup page tags both generated
    types so they're never mistaken for a real capture.
  - `mitre_techniques` — MITRE ATT&CK technique ID(s) associated with the
    event, where mapped (populated for Sysmon, AppLocker, Code Integrity,
    Windows Defender, and related detection-relevant events; blank
    elsewhere)
  - `acsc_priority_log` — `Yes` if this exact `(event_id, log)` appears in
    the ASD/ACSC "Priority logs for SIEM ingestion: Practitioner guidance"
    tables (Microsoft Domain Controller; AD & Domain Service Security Logs;
    Microsoft Windows endpoint logs; Windows DNS server analytic event
    logs), blank otherwise. The web lookup page has a toggle to show only
    these events.
  - `nist_800_53_au` — NIST SP 800-53 Audit and Accountability (AU) control
    ID(s) most relevant to the event: `AU-9` (Protection of Audit
    Information) for log-clearing/log-service events, `AU-8` (Time Stamps)
    for clock-change events, and `AU-2, AU-3, AU-12` (the standard "what to
    audit and how to generate it" triad) applied at the audit-subcategory
    level via `data/reference/audit_configuration.csv` — not a substitute
    for a full compliance assessment.

- `data/reference/audit_configuration.csv` / `.json` — how to configure
  auditing to collect events, one row per audit subcategory (or
  product-specific setting): the Group Policy / registry path, the steps to
  enable it, the event IDs it produces, a reference URL where available,
  and its NIST 800-53 AU control mapping. See
  `docs/audit-configuration-guide.md` for the readable version.
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
lookup page: search all 4,737 events by ID or keyword, filter by log/category,
toggle to show only ASD/ACSC priority logs, and view full detail —
description, sample log text, MITRE ATT&CK mapping, and how-to-collect
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

Also cross-referenced against NSA's `Event-Forwarding-Guidance`
(`Events/RecommendedEvents.csv` on GitHub, the companion dataset to NSA's
"Spotting the Adversary with Windows Event Log Monitoring"). About 55% of
its 205 individual event IDs were already covered; the rest opened up
several new log channels not previously in the catalogue — WLAN-AutoConfig,
CAPI2 (certificate chain building), NetworkProfile, TerminalServices-
RDPClient, USB-USBHUB3-Analytic, Kernel-PnP device configuration, LSA/
Operational, CertificationAuthority, RemoteAccess (RRAS/RADIUS), and
Application-Experience/Program-Inventory — plus boot/shutdown Kernel-
General events, Windows Firewall rule-change events, and further Windows
Defender and Windows Update failure events. A few NSA rows that
duplicated an event ID already covered by another source, but with a
generic or mismatched label (e.g. "Exception Raised" for what are
actually distinct PowerShell script-block-logging events already
correctly described), were treated as a labeling artifact and skipped in
favor of the existing, more specific entry.

Finally, cross-checked against a broader set of sources: **Microsoft's
official Advanced Audit Policy Configuration reference** (used to bring
`audit_policy_matrix.csv` to full coverage of all ~61 official
subcategories — added the 6 that were missing: Audit PNP Activity, Audit
Token Right Adjustment, Audit User / Device Claims, Audit Group
Membership, Audit Removable Storage, and Audit Central Access Policy
Staging, including two genuinely new events, 4626 and 4818, and
correcting a miscategorized 4703); **DISA's Windows STIG** (confirmed it
mandates Success/Failure settings for a subset of that same official
subcategory list rather than introducing separate event IDs, so no
additional events were needed); **community Sysmon configs**
(SwiftOnSecurity, Olaf Hartong — confirmed full coverage of the fixed
Sysmon 1-29 schema, no new IDs); and a bounded sample of **Splunk
Security Content (ESCU)** detections (GitHub code search and
research.splunk.com were both inaccessible in this environment without
repository approval, so this was a representative sample rather than the
full ~400-detection corpus — every EventCode found was already covered).

**NIST SP 800-53 AU controls** and **MITRE ATT&CK** aren't event-ID lists,
so instead of a gap-fill pass they were added as enrichment: the
`nist_800_53_au` field (see above) and an expanded `mitre_techniques`
pass covering ~85 additional clearly technique-relevant events (logon,
account/group management, Kerberos ticket operations, process/service/
scheduled-task creation, AppLocker/Code Integrity blocks, WMI activity,
PowerShell script-block logging, Zerologon-hardening, log clearing, and
several others) — left blank on purely diagnostic/operational events
(transport-layer detail, database internals, DHCP/DNS configuration, and
similar) where a technique mapping would be a stretch.

## Bulk ETW manifest import

A full Windows Server 2019 (1809, build 17763.1457) ETW event manifest
export — 45,958 event definitions across 813 providers, covering every
registered ETW provider on the system, not just security-relevant ones —
was cross-referenced and partially ingested. Given the scale (roughly 55x
the size of the curated catalogue at the time), the import was bounded to
security/audit-relevant channels only, identified by provider/channel name
(NTLM, Kerberos, Windows Hello for Business, Group Policy, WinRM, DHCP
Client, LDAP Client, Winlogon, UAC, Credential/Device Guard, IPsec,
Terminal Services variants, Smart Card, DPAPI, Hyper-V security-relevant
channels, and more) — adding 2,709 new events across ~130 new log
channels. Excluded: ~700 non-security providers (codecs, shell UI,
hardware/driver diagnostics, etc.), ~600 pure-ETW-trace events with no
Windows Event Log channel (not viewable in Event Viewer), and a handful
of rows whose channel name in the export was a generic placeholder
("Operational", "Admin", "Debug") rather than a real channel path.

The same treatment was applied to a second manifest export, this time
from Windows 11 24H2 Pro (build 26100.1742) — 52,405 events across 870
providers. The same security-adjacent channel filter added a further
1,198 new events (deduplicated against everything already in the
catalogue, including the Server 2019 import): full coverage of Windows
11-era security surfaces like WebAuthN, Windows Hello for Business
(including its Debug channel), BitLocker (encryption/decryption
lifecycle events previously missing), WLAN-AutoConfig diagnostics,
Privacy-Auditing, and Hyper-V VID admin/analytic channels. One channel
name collision was caught and fixed: the export truncated
`Microsoft-Windows-BitLocker-API`'s channel to the bare, ambiguous name
"Management" — renamed to `Microsoft-Windows-BitLocker-API/Management`
to avoid colliding with any other provider that might use the same
generic channel label in a future import.

These rows use `sample_type: template` — the manifest's own message
string, reformatted with the header fields and a best-effort line-break
fix for a source data quality issue (the export had stripped the original
message template's line breaks, causing segments to visually run
together; fixed by inserting a break wherever a placeholder or
punctuation mark was immediately followed by a capital letter). Unlike
the curated entries, these have no `how_to_collect`, `mitre_techniques`,
`nist_800_53_au`, or `acsc_priority_log` mapping — that enrichment was
done deliberately for the smaller curated set and hasn't been extended to
this bulk import.
