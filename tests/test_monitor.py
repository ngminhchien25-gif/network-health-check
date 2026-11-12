import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netcheck.monitor import CheckOutcome, EXIT_CRITICAL, EXIT_MAIL_FAILED, run_once, watch
from netcheck.notify import build_subject
from netcheck.state import DeviceResult as R, StateStore

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def at(minutes):
    return T0 + timedelta(minutes=minutes)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "state.json"

    def tearDown(self):
        self.dir.cleanup()

    def store(self, **kw):
        return StateStore(self.path, **kw)

    def test_first_run_ok_is_silent(self):
        self.assertEqual(self.store().update([R("R1", "OK")], at(0)), [])

    def test_first_run_bad_alerts(self):
        ch = self.store().update([R("R1", "CRITICAL", ["down"])], at(0))
        self.assertEqual([c.kind for c in ch], ["new"])

    def test_degrade_then_recover_with_duration(self):
        s = self.store()
        s.update([R("R1", "OK")], at(0))
        d = s.update([R("R1", "CRITICAL", ["Fa1/0 down"])], at(5))
        self.assertEqual((d[0].kind, d[0].old, d[0].new), ("degraded", "OK", "CRITICAL"))
        self.assertEqual(s.update([R("R1", "CRITICAL", ["Fa1/0 down"])], at(10)), [])  # không lặp
        r = s.update([R("R1", "OK")], at(15))
        self.assertEqual(r[0].kind, "recovered")
        self.assertEqual(r[0].duration_s, 600)
        self.assertEqual(r[0].resolved, ["Fa1/0 down"])

    def test_improved(self):
        s = self.store()
        s.update([R("R1", "CRITICAL", ["a"])], at(0))
        self.assertEqual(s.update([R("R1", "WARNING", ["b"])], at(5))[0].kind, "improved")

    def test_numbers_in_findings_do_not_trigger(self):
        s = self.store()
        s.update([R("R1", "WARNING", ["latency 41 ms to 8.8.8.8"])], at(0))
        self.assertEqual(s.update([R("R1", "WARNING", ["latency 55 ms to 8.8.8.8"])], at(5)), [])

    def test_new_finding_same_status(self):
        s = self.store()
        s.update([R("R1", "WARNING", ["no default route"])], at(0))
        ch = s.update([R("R1", "WARNING", ["no default route", "OSPF route missing"])], at(5))
        self.assertEqual(ch[0].kind, "findings_changed")
        self.assertEqual(ch[0].added, ["OSPF route missing"])

    def test_flap_protection(self):
        s = self.store(confirm_runs=2)
        s.update([R("R1", "OK")], at(0))
        self.assertEqual(s.update([R("R1", "CRITICAL", ["x"])], at(5)), [])     # lần 1: chưa báo
        self.assertEqual(s.update([R("R1", "OK")], at(10)), [])                 # tự hết: không báo
        self.assertEqual(s.update([R("R1", "CRITICAL", ["x"])], at(15)), [])
        self.assertEqual(s.update([R("R1", "CRITICAL", ["x"])], at(20))[0].kind, "degraded")

    def test_reminder(self):
        s = self.store(reminder_after_s=3600)
        s.update([R("R1", "OK")], at(0))
        s.update([R("R1", "CRITICAL", ["x"])], at(5))
        self.assertEqual(s.update([R("R1", "CRITICAL", ["x"])], at(30)), [])
        self.assertEqual(s.update([R("R1", "CRITICAL", ["x"])], at(66))[0].kind, "reminder")

    def test_persistence_and_corrupt_file(self):
        s = self.store()
        s.update([R("R1", "OK")], at(0))
        s.save()
        s2 = self.store()
        self.assertEqual(s2.update([R("R1", "CRITICAL", ["x"])], at(5))[0].kind, "degraded")
        self.path.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.store().devices, {})


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.dir.name) / "s.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_mail_only_on_change(self):
        sent = []
        notifier = lambda ch, res, rp: sent.append(ch)
        seq = iter([[R("R1", "OK")], [R("R1", "OK")], [R("R1", "CRITICAL", ["down"])],
                    [R("R1", "CRITICAL", ["down"])], [R("R1", "OK")]])
        run = lambda: run_once(lambda: CheckOutcome(next(seq)), self.store, notifier)
        codes = [run() for _ in range(5)]
        self.assertEqual(len(sent), 2)                         # degraded + recovered
        self.assertEqual(codes, [0, 0, EXIT_CRITICAL, EXIT_CRITICAL, 0])

    def test_mail_failure_retries_next_run(self):
        calls = []

        def flaky(ch, res, rp):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("smtp down")

        run_once(lambda: CheckOutcome([R("R1", "OK")]), self.store, flaky)
        code = run_once(lambda: CheckOutcome([R("R1", "CRITICAL", ["x"])]), self.store, flaky)
        self.assertEqual(code, EXIT_MAIL_FAILED)
        code = run_once(lambda: CheckOutcome([R("R1", "CRITICAL", ["x"])]), self.store, flaky)
        self.assertEqual(code, EXIT_CRITICAL)
        self.assertEqual(len(calls), 2)                        # lần 2 đã báo lại thành công

    def test_watch_survives_check_errors_and_alerts_once(self):
        sent = []

        def boom():
            raise ConnectionError("collector broke")

        watch(boom, self.store, lambda ch, res, rp: sent.append(ch),
              interval_s=0, max_runs=5, error_alert_after=3)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][0].device, "NetCheck")

    def test_subject(self):
        from netcheck.state import Change
        c = Change("R2", "degraded", "OK", "CRITICAL", ["x"])
        self.assertEqual(build_subject([c]), "[NetCheck][CRITICAL] R2: OK -> CRITICAL")
        r = Change("R2", "recovered", "CRITICAL", "OK", [])
        self.assertTrue(build_subject([r]).startswith("[NetCheck][RECOVERED]"))


if __name__ == "__main__":
    unittest.main()