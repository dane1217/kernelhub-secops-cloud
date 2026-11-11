# Detection engine v1.0.0

The executable catalog in `backend/secops/rules.py` is authoritative. `/rules` returns required data, exact logic, severity, false positives, investigation guidance and ATT&CK references for each rule. Every resulting alert stores that version and an effective-tuning snapshot; there is no AI risk score.

| ID | Required signal | Logic | Severity / rationale | ATT&CK |
|---|---|---|---|---|
| KH-001 | Windows 4625, parsed Linux SSH failure, normalized auth.failure | 5 failures / 5 min, same user + source IP | Medium; potential password guessing | T1110 |
| KH-002 | Above failures + normalized/Windows non-RDP auth.success | Success after 5 failures / 5 min, same user + source IP | High; possible successful guessing | T1078 |
| KH-003 | Windows 4728/4732/4756 privileged group RID or normalized explicit addition | One group.privileged_add | High; privilege change | T1098 |
| KH-004 | Explicit normalized account.privileged_create | One privileged-account creation | High; privileged persistence | T1136 |
| KH-005 | Windows 1102 or normalized log.clear | One audit-log clear | High; potential evidence removal | T1070.001 |
| KH-006 | Windows 4688/4104 with command text or normalized process.start | powershell/pwsh + -enc/-encodedcommand/-e + base64-shaped argument | High; obscured script execution | T1059.001 |
| KH-007 | Defender 5001 or normalized security.disable | One explicit security-control disable | High; defense impairment | T1562.001 |
| KH-008 | Windows 4624 logon type 10 or normalized remote.login | One remote interactive login, review required | Medium; remote access review signal | T1021.001 |
| KH-009 | Linux/normalized auth.failure with user=root | One root login failure | Medium; sensitive account targeted | T1110 |
| KH-010 | Windows 4720 or normalized account.create | 3 creations / 5 min, same host | Medium; unusual provisioning burst | T1136 |

These are investigation signals, not proof of compromise. Windows 4720 alone never asserts that a new account is privileged. KH-008 does not implement behavioral baselines and therefore cannot establish that remote access was unexpected. Authentication/administration activity can legitimately match every rule. Review change tickets, service-account behavior and customer context; tune thresholds and excluded users accordingly. The catalog provides specific guidance for each signal.

## Timing, retries and grouping

- Source time defines the inclusive rolling five-minute correlation window. KH-002 requires failures strictly before success. Future timestamps over five minutes are rejected. Events older than 24 hours at ingestion remain searchable historical events and do not produce automatic alerts.
- In-order or late-within-24-hour events are evaluated against arrived SQL history. A late failure re-evaluates arrived successes in the surrounding five minutes. Missing user/IP suppresses authentication correlation; missing host suppresses the creation-burst rule. Single-event rules can match without those fields.
- A worker may see other accepted events before those other events are indexed. Supporting event documents are still accessible from SQL; archival/index completion for each event can lag.
- Original external IDs are deduplicated per tenant/source. Worker retries upsert archive/search targets; a stable alert fingerprint prevents duplicate alerts for the same rule/version/tuning/group/ten-minute UTC bucket.
- Rolling detection windows and ten-minute grouping buckets are different. A sequence spanning a grouping boundary can create two alerts. This is explicit fixed-bucket grouping, not global sequence deduplication. Changed tuning creates a distinct fingerprint.
- Evidence appended to an existing alert is audited. Correlation reads a maximum of 10,000 events in its ten-minute surrounding SQL window; overflow produces an audit entry and skips that evaluation. This is a known coverage limit requiring a monitored redesign before high-rate sources.
- Rules can be disabled, suppressed until a timestamp, tuned for supported threshold counts and supplied excluded users. Live evaluation uses the settings when processed; suppression compares the event's ingestion time. Historical dry-run tests use baseline catalog logic and selected tenant events without creating alerts.

## Fixtures and scope

`tests/test_rules.py` exercises positive and negative fixtures for all ten rules, missing fields, duplicate IDs, time windows and parser mappings. `tests/test_workflows.py` tests persisted evidence, live alert creation, late failures, replay and suppression-by-disable. Static collector examples are in `fixtures/`; the synthetic sender refreshes timestamps.

**Sigma compatibility: none implemented.** No YAML importer or general condition engine is exposed. A future scoped integration must define allowed field mappings, boolean operators and aggregation constructs and reject everything else. ATT&CK references are justified by the recorded action, not inferred attribution.
