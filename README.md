# Winevent-catalogue

A structured catalogue of Windows Event Log IDs, built from a personal MS
Server administration notebook (TiddlyWiki export). Covers Security auditing
events (mapped to their Group Policy audit subcategories), DHCP Server
events, Removable Media / Plug-and-Play device events, Network Location
Awareness (NLA) events, Terminal Services / RDS session events, and System
shutdown/restart events.

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
  - `sample` — a real or representative sample of the event's rendered text, where available
  - `reference` — pointer to related configuration notes or docs

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

## Source

Extracted from a TiddlyWiki 5 export ("MSServer" notebook) covering Windows
Server administration topics. Only the Event Log / Event ID related tiddlers
were used to build this catalogue.
