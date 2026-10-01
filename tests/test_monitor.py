import threading
import time

import pytest
from conftest import KEY

from otguard import baseline, ledger, simulate
from otguard.monitor import Engine


def approve(cfg, path):
    baseline.approve(cfg, path, KEY, by="J. Komal", reason="initial")


def actions(cfg):
    return [r["event"]["action"] for r in ledger.read(cfg.ledger)]


def make_engine(cfg):
    return Engine(cfg, KEY, log=lambda *_: None)


def test_clean_start(workspace, project_file):
    approve(workspace, project_file)
    assert make_engine(workspace).start()
    assert actions(workspace) == ["engine-started"]


def test_tampering_while_stopped_is_reported_and_the_file_is_left_alone(workspace, project_file):
    approve(workspace, project_file)
    simulate.apply(project_file, "raise-setpoint")
    tampered = project_file.read_bytes()

    assert make_engine(workspace).start()

    assert actions(workspace) == ["engine-started", "plc-logic-drift"]
    assert project_file.read_bytes() == tampered  # v1 overwrote it with the baseline, erasing the evidence
    alert = list(ledger.read(workspace.ledger))[-1]
    assert alert["otguard"]["severity"] == "CRITICAL"
    assert alert["threat"]["technique"] == [{"id": "T0836", "name": "Modify Parameter"}]
    assert alert["otguard"]["changes"][0]["before"] == "1000"


def test_a_drift_never_becomes_the_baseline(workspace, project_file):
    """v1 re-baselined to the tampered file after alerting, so the attacker's logic became 'trusted'."""
    approve(workspace, project_file)
    engine = make_engine(workspace)
    engine.start()
    simulate.apply(project_file, "invert-contact")
    assert engine.check(project_file)["event"]["action"] == "plc-logic-drift"
    assert engine.check(project_file) is None  # same drift: reported once
    simulate.apply(project_file, "raise-setpoint")  # a second change on top
    second = engine.check(project_file)
    assert {c["kind"] for c in second["otguard"]["changes"]} == {
        "rung_modified",
        "tag_value",
    }  # still vs approved
    assert baseline.load_verified(workspace, project_file, KEY)[1]["reason"] == "initial"


def test_restoring_the_approved_file_is_recorded(workspace, project_file):
    approve(workspace, project_file)
    original = project_file.read_bytes()
    engine = make_engine(workspace)
    engine.start()
    simulate.apply(project_file, "inhibit-task")
    engine.check(project_file)
    project_file.write_bytes(original)
    assert engine.check(project_file)["event"]["action"] == "plc-logic-restored"


def test_unreadable_and_missing_files_are_alerts(workspace, project_file):
    approve(workspace, project_file)
    engine = make_engine(workspace)
    engine.start()
    project_file.write_bytes(b"<RSLogix5000Content><Controller>")
    record = engine.check(project_file)
    assert record["event"]["action"] == "plc-project-unreadable"
    assert "not well-formed" in record["otguard"]["error"]
    project_file.unlink()
    assert engine.check(project_file)["event"]["action"] == "plc-project-missing"


def test_an_untrusted_baseline_stops_the_engine(workspace, project_file):
    approve(workspace, project_file)
    copy, _ = baseline.paths(workspace, project_file)
    copy.write_bytes(copy.read_bytes() + b"\n")
    assert make_engine(workspace).start() is False
    assert actions(workspace) == ["baseline-invalid"]


def test_benign_re_export_raises_nothing(workspace, project_file):
    approve(workspace, project_file)
    engine = make_engine(workspace)
    engine.start()
    simulate.apply(project_file, "benign-export")
    assert engine.check(project_file) is None
    assert actions(workspace) == ["engine-started"]


# --- the real file watcher -----------------------------------------------------


@pytest.fixture
def running(workspace, project_file):
    approve(workspace, project_file)
    engine = make_engine(workspace)
    assert engine.start()
    thread = threading.Thread(target=engine.run, daemon=True)
    thread.start()
    time.sleep(0.5)
    yield engine
    engine.stop()
    thread.join(timeout=5)


def wait_for(cfg, action, count=1, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if actions(cfg).count(action) >= count:
            return True
        time.sleep(0.1)
    return False


def test_watcher_sees_in_place_writes(running, workspace, project_file):
    simulate.apply(project_file, "disable-interlock")
    assert wait_for(workspace, "plc-logic-drift")


def test_watcher_sees_atomic_replace(running, workspace, project_file):
    """Editors save by writing a temporary file and renaming it; v1 ignored that event."""
    simulate.apply(project_file, "invert-contact", atomic=True)
    assert wait_for(workspace, "plc-logic-drift")


def test_watcher_sees_deletion(running, workspace, project_file):
    project_file.unlink()
    assert wait_for(workspace, "plc-project-missing")


def test_periodic_rescan_catches_changes_without_events(workspace, project_file, monkeypatch):
    """Some mounts never deliver file events; the rescan is the safety net."""
    import otguard.monitor as monitor

    class Deaf:
        def schedule(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def join(self):
            pass

    monkeypatch.setattr(monitor, "Observer", Deaf)
    object.__setattr__(workspace, "rescan_seconds", 0.5)
    approve(workspace, project_file)
    engine = make_engine(workspace)
    engine.start()
    thread = threading.Thread(target=engine.run, daemon=True)
    thread.start()
    simulate.apply(project_file, "shorten-timer")
    try:
        assert wait_for(workspace, "plc-logic-drift")
    finally:
        engine.stop()
        thread.join(timeout=5)


def test_ledger_is_intact_after_a_session(running, workspace, project_file):
    simulate.apply(project_file, "remove-interlock")
    assert wait_for(workspace, "plc-logic-drift")
    assert ledger.verify(workspace.ledger, KEY) == []
