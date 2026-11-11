import unittest
from datetime import timedelta
from secops.events import InvalidEvent, normalize, now, parse_time
from secops.rules import BY_ID, RULES, evidence_for


class RuleFixtures(unittest.TestCase):
    def event(self, action, i=0, **fields):
        result = normalize({"action": action, "timestamp": (parse_time(now())-timedelta(seconds=100-i)).isoformat(),
                            "user": "alice", "source_ip": "192.0.2.10", "host": "host", **fields}, "normalized", now())
        result["id"] = str(i)
        return result

    def test_all_ten_rules_have_positive_and_negative_fixtures(self):
        self.assertEqual(10, len(RULES))
        for rule in RULES:
            with self.subTest(rule=rule.id):
                fields = {"command_line": "powershell.exe -enc SQBFAFgA"} if rule.id == "KH-006" else {"user": "root"} if rule.id == "KH-009" else {}
                target = self.event(rule.action, 9, **fields)
                history = [self.event("auth.failure" if rule.id == "KH-002" else rule.action, i, **fields) for i in range(rule.threshold)]
                if rule.id != "KH-002":
                    history[-1] = target
                self.assertTrue(evidence_for(rule, target, history))
                self.assertFalse(evidence_for(rule, self.event("system.message"), history))
                if rule.threshold > 1:
                    self.assertFalse(evidence_for(rule, target, history[:1]))

    def test_missing_correlation_and_duplicate_ids(self):
        rule = BY_ID["KH-001"]
        event = self.event("auth.failure", user=None)
        self.assertEqual([], evidence_for(rule, event, [event]*10))
        event = self.event("auth.failure")
        self.assertEqual([], evidence_for(rule, event, [event]*10))

    def test_outside_window_historical_and_future(self):
        event = self.event("auth.failure")
        history = [self.event("auth.failure", i) for i in range(5)]
        for h in history:
            h["source_time"] = (parse_time(event["source_time"])-timedelta(minutes=6)).isoformat()
        self.assertFalse(evidence_for(BY_ID["KH-001"], event, history))
        event = self.event("log.clear")
        event["historical"] = True
        self.assertFalse(evidence_for(BY_ID["KH-005"], event, [event]))
        with self.assertRaises(InvalidEvent):
            normalize({"action": "log.clear", "timestamp": (parse_time(now())+timedelta(hours=1)).isoformat()}, "normalized", now())

    def test_linux_and_windows_parser_contracts(self):
        linux = normalize({"timestamp": now(), "message": "sshd[42]: Failed password for alice from 192.0.2.1 port 50000 ssh2"}, "linux", now())
        self.assertEqual(("auth.failure", "alice", "192.0.2.1"), (linux["action"], linux["user"], linux["source_ip"]))
        win = {"timestamp": now(), "winlog": {"event_id": 4732, "event_data": {"TargetSid": "S-1-5-32-544", "SubjectUserName": "admin"}}}
        self.assertEqual("group.privileged_add", normalize(win, "windows", now())["action"])
        win["winlog"]["event_data"]["TargetSid"] = "S-1-5-21-513"
        self.assertEqual("system.message", normalize(win, "windows", now())["action"])
        win["winlog"]["event_id"] = 4720
        self.assertEqual("account.create", normalize(win, "windows", now())["action"])

    def test_nonfinite_and_invalid_structured_fields_are_rejected(self):
        for fields, kind in (({"extra":float("nan")},"normalized"), ({"event_id":True},"normalized"), ({"winlog":[]},"windows")):
            with self.subTest(fields=fields), self.assertRaises(InvalidEvent):
                normalize({"timestamp":now(),"action":"system.message",**fields},kind,now())
