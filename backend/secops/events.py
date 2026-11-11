"""Versioned normalization. Treat collector fields as untrusted data."""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone, timedelta

SCHEMA_VERSION = "1.0"
PARSER_VERSION = "1.0.0"
SENSITIVE = re.compile(r"password|passwd|secret|token|authorization|cookie|private.?key|credential", re.I)
INLINE_SECRET = re.compile(r"(?i)(password|passwd|token|secret|api_key)(\s*[=:]\s*)([^\s;,]+)")
ACTIONS = {"auth.failure", "auth.success", "group.privileged_add", "account.privileged_create",
           "log.clear", "process.start", "security.disable", "remote.login", "account.create", "system.message"}
WINDOWS_ACTIONS = {4625: "auth.failure", 4624: "auth.success", 4728: "group.privileged_add",
                   4732: "group.privileged_add", 4756: "group.privileged_add", 4720: "account.create",
                   1102: "log.clear", 4688: "process.start", 4104: "process.start", 5001: "security.disable"}
PRIVILEGED_RIDS = {"512", "518", "519", "544", "548", "549", "550", "551"}


class InvalidEvent(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def parse_time(value):
    if not isinstance(value, str):
        raise InvalidEvent("timestamp must be an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidEvent("invalid timestamp") from exc
    if dt.tzinfo is None:
        raise InvalidEvent("timestamp requires timezone")
    return dt.astimezone(timezone.utc)


def redact(value, depth=0):
    if depth > 12:
        return "[depth limit]"
    if isinstance(value, dict):
        return {str(k)[:100]: "[REDACTED]" if SENSITIVE.search(str(k)) else redact(v, depth+1)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth+1) for v in value[:100]]
    if isinstance(value, str):
        return INLINE_SECRET.sub(r"\1\2[REDACTED]", value[:8192])
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)[:500]


def normalize(raw, kind, received_at):
    if not isinstance(raw, dict):
        raise InvalidEvent("event must be an object of at most 32 KiB")
    try:
        serialized = json.dumps(raw, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise InvalidEvent("event must contain finite JSON values within supported nesting") from exc
    if len(serialized) > 32768:
        raise InvalidEvent("event must be an object of at most 32 KiB")
    if any(k in raw for k in ("org_id", "tenant_id", "workspace_id")):
        raise InvalidEvent("tenant and workspace are derived from the credential")
    data = dict(raw)
    if kind == "windows":
        win = raw.get("winlog", {})
        if not isinstance(win, dict):
            raise InvalidEvent("windows requires structured winlog object")
        fields = win.get("event_data", {})
        if not isinstance(fields, dict):
            raise InvalidEvent("windows requires structured winlog.event_data")
        try:
            code = int(win.get("event_id", raw.get("event_code", 0)))
        except (ValueError, TypeError) as exc:
            raise InvalidEvent("invalid Windows event code") from exc
        action = WINDOWS_ACTIONS.get(code)
        if not action:
            raise InvalidEvent("unsupported Windows event code")
        if action == "group.privileged_add" and str(fields.get("TargetSid", "")).split("-")[-1] not in PRIVILEGED_RIDS:
            action = "system.message"
        data.update(action=action, timestamp=raw.get("timestamp", raw.get("@timestamp")),
                    user=fields.get("TargetUserName", fields.get("SubjectUserName")),
                    host=raw.get("host", win.get("computer_name")), source_ip=fields.get("IpAddress"),
                    command_line=fields.get("CommandLine", fields.get("ScriptBlockText", "")),
                    logon_type=str(fields.get("LogonType", "")))
        if code == 4624 and data["logon_type"] == "10":
            data["action"] = "remote.login"
    elif kind == "linux":
        message = str(raw.get("message", ""))
        failure = re.search(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\da-fA-F.:]+)", message)
        success = re.search(r"Accepted (?:password|publickey) for (\S+) from ([\da-fA-F.:]+)", message)
        matched = failure or success
        data.update(action="auth.failure" if failure else "auth.success" if success else "system.message")
        if matched:
            data.update(user=matched[1], source_ip=matched[2])
    action = data.get("action")
    if action not in ACTIONS:
        raise InvalidEvent("unsupported action")
    source_time = parse_time(data.get("timestamp"))
    if source_time > parse_time(received_at) + timedelta(minutes=5):
        raise InvalidEvent("timestamp exceeds five minute clock skew")
    def field(name):
        value = data.get(name)
        if isinstance(value, dict) and name == "host":
            value = value.get("name")
        if value is not None and not isinstance(value, str):
            raise InvalidEvent(f"{name} must be text")
        if value and len(value) > (8192 if name == "command_line" else 256):
            raise InvalidEvent(f"{name} too long")
        return redact(value) if value else None
    source_ip, destination_ip = field("source_ip"), field("destination_ip")
    for address in (source_ip, destination_ip):
        if address and address != "-":
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise InvalidEvent("invalid IP address") from exc
    external = raw.get("event_id")
    if external is None:
        external = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if isinstance(external, bool) or not isinstance(external, (str, int)) or not 1 <= len(str(external)) <= 256:
        raise InvalidEvent("invalid event_id")
    severity = data.get("severity", "info")
    outcome = data.get("outcome", "failure" if action == "auth.failure" else "success" if action in ("auth.success", "remote.login") else "unknown")
    if severity not in ("info", "low", "medium", "high", "critical") or outcome not in ("success", "failure", "unknown"):
        raise InvalidEvent("invalid severity or outcome")
    return {"external_id": str(external), "source_time": source_time.isoformat(timespec="microseconds"),
            "received_at": received_at, "action": action, "category": action.split(".")[0],
            "host": field("host"), "user": field("user"), "source_ip": None if source_ip == "-" else source_ip,
            "destination_ip": None if destination_ip == "-" else destination_ip,
            "outcome": outcome, "severity": severity, "command_line": field("command_line"),
            "schema_version": SCHEMA_VERSION, "parser_version": PARSER_VERSION,
            "data_mode": "synthetic" if raw.get("synthetic") is True else "live",
            "historical": source_time < parse_time(received_at) - timedelta(hours=24)}
