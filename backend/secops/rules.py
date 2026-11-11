"""Deterministic rules; no AI or unrestricted query language."""
from dataclasses import asdict, dataclass
from datetime import timedelta
import re
from .events import parse_time


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    action: str
    technique: str
    logic: str
    false_positives: str
    guidance: str
    source: str = "normalized or documented Windows/Linux parser"
    version: str = "1.0.0"
    window_seconds: int = 300
    threshold: int = 1

    def document(self):
        return asdict(self)


RULES = (
 Rule("KH-001", "Repeated failed authentication", "medium", "auth.failure", "T1110", "5 failures by user + source IP within 5 minutes", "Stale service credentials, user mistakes", "Check source IP ownership and account history", threshold=5),
 Rule("KH-002", "Successful login following failures", "high", "auth.success", "T1078", "Success after 5 failures for user + source IP within 5 minutes", "User corrected a forgotten password", "Validate login with the user and inspect session activity", threshold=5),
 Rule("KH-003", "Privileged group membership changed", "high", "group.privileged_add", "T1098", "One privileged group addition; Windows RID allowlist or trusted normalized telemetry", "Approved administration", "Validate change ticket, group SID, actor and target"),
 Rule("KH-004", "New privileged account", "high", "account.privileged_create", "T1136", "One explicit privileged account creation from normalized telemetry", "Approved provisioning", "Verify creator and privileges; Windows 4720 alone is insufficient", source="normalized telemetry asserting privileged creation"),
 Rule("KH-005", "Security audit log cleared", "high", "log.clear", "T1070.001", "One security log clearing event", "Approved log maintenance", "Preserve forwarded events and identify actor"),
 Rule("KH-006", "Encoded PowerShell command", "high", "process.start", "T1059.001", "PowerShell/pwsh command with -enc, -encodedcommand or -e base64 argument", "Management scripts", "Inspect parent process and decode in an isolated analysis tool"),
 Rule("KH-007", "Security control disabled", "high", "security.disable", "T1562.001", "One explicit security control disable event", "Approved maintenance", "Validate endpoint protection state and actor"),
 Rule("KH-008", "Remote interactive login", "medium", "remote.login", "T1021.001", "One Windows type 10 or normalized remote login; review signal, not proof of compromise", "Routine remote administration", "Check source address, authorization and login schedule"),
 Rule("KH-009", "Root authentication failure", "medium", "auth.failure", "T1110", "One failure for root", "Legitimate administrator typo", "Check whether direct root access is authorized"),
 Rule("KH-010", "Burst of account creation", "medium", "account.create", "T1136", "3 account creations on the same host within 5 minutes", "Bulk onboarding", "Verify provisioning request and initiating account", threshold=3),
)
BY_ID = {r.id: r for r in RULES}


def matches(rule, event):
    if event.get("historical") or event["action"] != rule.action:
        return False
    if rule.id == "KH-006":
        command = event.get("command_line") or ""
        return bool(re.search(r"(?i)\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b.*\s-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}", command))
    if rule.id == "KH-009":
        return event.get("user") == "root"
    return True


def correlation_key(rule, event):
    if rule.id in ("KH-001", "KH-002"):
        return (event["user"], event["source_ip"]) if event.get("user") and event.get("source_ip") else None
    if rule.id == "KH-010":
        return (event["host"],) if event.get("host") else None
    return (event["id"],)


def evidence_for(rule, event, history, threshold=None):
    if not matches(rule, event):
        return []
    group = correlation_key(rule, event)
    if group is None:
        return []
    required = threshold if threshold is not None else rule.threshold
    if rule.id not in ("KH-001", "KH-002", "KH-010"):
        return [event["id"]]
    end = parse_time(event["source_time"])
    start = end - timedelta(seconds=rule.window_seconds)
    action = "auth.failure" if rule.id == "KH-002" else rule.action
    candidates = {x["id"]: x for x in history if x["action"] == action and not x.get("historical")
                  and correlation_key(rule, x) == group and start <= parse_time(x["source_time"]) <= end
                  and (rule.id != "KH-002" or parse_time(x["source_time"]) < end)}
    ids = [x["id"] for x in sorted(candidates.values(), key=lambda x: (x["source_time"], x["id"]))]
    return ids + ([event["id"]] if rule.id == "KH-002" else []) if len(ids) >= required else []
