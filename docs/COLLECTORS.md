# Collector interface and parser support

This platform does not install a privileged custom endpoint agent. It accepts authenticated HTTPS JSON arrays from maintained collectors. The backend parser tests validate documented record shapes; **the sample collector configurations still need validation on real Windows/Linux hosts with the selected collector releases**.

## Linux

`collectors/fluent-bit-linux.conf` uses Fluent Bit's systemd input, persistent journal position, a disk-backed buffer and HTTPS JSON-array output. Configure KH_INGEST_HOST and KH_INGEST_KEY through the service manager's protected environment, never source control. Give the collector only the journal/log access it needs and ownership of its checkpoint/buffer directories. Create a platform source with kind=linux.

The example selects ssh/sshd units. Change the filter for your distribution and create a separately managed source for wider system logs if required. Unknown system messages normalize to system.message and remain searchable without authentication detections. Confirm that Fluent Bit's JSON date field is `timestamp` and that messages/hosts become `message`/`host`.

Supported SSH messages are English OpenSSH forms `Failed password/publickey for [invalid user] USER from IP` and `Accepted password/publickey for USER from IP`. PAM, sudo, localized logs and arbitrary vendor formats are not semantically parsed. They can be forwarded as system.message or mapped into the normalized schema by a reviewed upstream transform. Generic Linux authentication messages do not prove privileged account creation.

## Windows

`collectors/vector-windows.toml` uses Vector's native Windows Event Log source, a small reviewed remap and persistent disk buffer. Upstream marks this source beta. Configure the same protected environment variables, run on Windows, and grant appropriate Event Log Readers/channel rights; some channels and audit settings need administrator setup. Preserve checkpoints and disk buffers across service restarts.

The remap moves Windows's numeric event type into `winlog.event_id`; it deliberately removes the root event_id so the backend does not incorrectly deduplicate all 4625 records as one record. The backend hashes canonical raw records when no stable external record ID is provided. For an audited deployment, map the host/channel/record identifier to a stable unique external ID after checking the installed collector's output schema.

Supported codes: 4624/4625 authentication; 4720 account creation; 4728/4732/4756 privileged-group membership; 1102 audit-log clear; 4688 process creation; 4104 PowerShell script block; 5001 Defender disabled. Required structured fields are `winlog.event_data`, for example TargetUserName/SubjectUserName, IpAddress, TargetSid, LogonType and CommandLine/ScriptBlockText. Event audit policy, command-line auditing, script-block logging and Defender channels must be enabled separately where appropriate. Missing telemetry cannot be detected by inference.

Privileged membership is asserted only for a small explicit SID/RID allowlist. 4720 is account.create, never privileged creation by itself. Type 10 login becomes remote.login and is not included in KH-002's auth.success sequence. Advanced correlation, local-group naming variations, provider-version field differences and process ancestry are out of scope.

## HTTPS output and delivery contract

Use Content-Type application/json and Authorization: Bearer SOURCE_KEY. Send an array of 1–100 objects, each no more than 32 KiB, total no more than 1 MiB. The Vector HTTP JSON character-delimited encoder must emit a JSON array; verify its exact wire payload with the installed version before enabling the source. Its sample is limited to one event per request. Do not add a second set of array brackets if the encoder already supplies them.

The API acknowledges only after the SQL transaction commits. A 202 does not promise indexing has completed. Retry timeouts, 429 and 5xx with the same IDs and bounded exponential backoff. Do not endlessly retry permanent 4xx parser failures; isolate/quarantine the offending record and surface an operator error. Maintained collectors differ in permanent-failure handling: configure alerts and verify their disk-buffer/backpressure/drop behavior. A permanent parser failure can poison a collector batch; the source/parser must be validated before scale-up.

Raw-event redaction is intentionally limited. Filter credentials and unnecessary personal data at source; do not transmit plaintext passwords. Network encryption and narrowly scoped source credentials are required outside the loopback developer stack.

## Future connectors

A new connector must emit the normalized v1 contract or add a versioned pure parser in `events.py`, with positive/negative fixtures, a source-scoped credential, a health/last_seen policy, rate/quota handling and safe raw-event redaction. No connector supplies a trusted tenant identifier. Cloud, firewall, identity and endpoint products require their own supported telemetry mappings and credentials; none are currently connected.

Official references: [Fluent Bit HTTP](https://docs.fluentbit.io/manual/data-pipeline/outputs/http), [Fluent Bit systemd](https://docs.fluentbit.io/manual/data-pipeline/inputs/systemd), [Vector Windows Event Log](https://vector.dev/docs/reference/configuration/sources/windows_event_log/), [Vector HTTP](https://vector.dev/docs/reference/configuration/sinks/http/).
