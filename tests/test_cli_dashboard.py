import json
from pathlib import Path

from conftest import KEY, sample_bytes

from otguard import config, dashboard, ledger
from otguard.cli import main

ROOT = Path(__file__).resolve().parent.parent


def setup_demo(tmp_path, monkeypatch) -> str:
    monkeypatch.setenv(config.KEY_ENV, KEY.decode())
    assert main(["demo", "init", str(tmp_path / "demo"), "--approve"]) == 0
    return str(tmp_path / "demo" / "otguard.toml")


def test_cli_flow(tmp_path, monkeypatch, capsys):
    cfg = setup_demo(tmp_path, monkeypatch)
    assert main(["--config", cfg, "check"]) == 0
    assert main(["--config", cfg, "demo", "attack", "disable-interlock", "--atomic"]) == 0
    capsys.readouterr()
    assert main(["--config", cfg, "check", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result[0]["status"] == "drift"
    assert result[0]["changes"][0]["technique"]["id"] == "T0889"

    assert main(["--config", cfg, "approve", "--by", "J. Komal", "--reason", "WO-7 accepted change"]) == 0
    out = capsys.readouterr().out
    assert "1 change(s) relative to the previous baseline were approved" in out
    assert main(["--config", cfg, "check"]) == 0
    assert main(["--config", cfg, "verify-ledger"]) == 0
    assert [r["event"]["action"] for r in ledger.read(config.load(cfg).ledger)] == [
        "baseline-approved",
        "baseline-approved",
    ]


def test_diff_command(tmp_path, capsys):
    a, b = tmp_path / "a.L5X", tmp_path / "b.L5X"
    a.write_bytes(sample_bytes())
    b.write_bytes(sample_bytes().replace(b"XIC(Temp_High)OTE", b"XIO(Temp_High)OTE"))
    assert main(["--config", str(tmp_path / "none.toml"), "diff", str(a), str(b)]) == 1
    assert "contact on Temp_High inverted" in capsys.readouterr().out
    assert main(["--config", str(tmp_path / "none.toml"), "diff", str(a), str(a)]) == 0


def test_missing_key_is_a_clear_error(tmp_path, monkeypatch, capsys):
    cfg = setup_demo(tmp_path, monkeypatch)
    monkeypatch.delenv(config.KEY_ENV)
    assert main(["--config", cfg, "check"]) == 2
    assert "OT_GUARD_SECRET_KEY is not set" in capsys.readouterr().err


# --- dashboard ----------------------------------------------------------------


def drift_record(diff_text: str) -> dict:
    return {
        "@timestamp": "2026-10-01T10:00:00Z",
        "event": {"kind": "alert", "action": "plc-logic-drift"},
        "message": "WaterPlant.L5X: 1 unapproved change(s)",
        "file": {"name": "WaterPlant.L5X"},
        "otguard": {
            "severity": "CRITICAL",
            "diff": diff_text,
            "changes": [
                {
                    "kind": "rung_modified",
                    "location": "MainProgram/MainRoutine rung 0",
                    "summary": "contact on Temp_High inverted (XIC -> XIO)",
                    "severity": "CRITICAL",
                    "before": "XIC(Temp_High)OTE(Cooling_Fan);",
                    "after": "XIO(Temp_High)OTE(Cooling_Fan);",
                    "technique": {"id": "T0889", "name": "Modify Program", "tactics": []},
                }
            ],
        },
        "threat": {
            "technique": [{"id": "T0889", "name": "Modify Program"}],
            "tactic": [{"name": "Persistence"}],
        },
    }


def test_dashboard_helpers_escape_attacker_controlled_text():
    html = dashboard.diff_html("+<img src=x onerror=alert(1)>\n-old\n context")
    assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert 'class="diff-add"' in html and 'class="diff-remove"' in html
    rows = dashboard.change_rows(drift_record(""))
    assert rows[0]["ATT&CK for ICS"] == "T0889 Modify Program"


def test_file_status_follows_the_latest_event():
    records = [drift_record("")]
    assert dashboard.file_status(records, ["WaterPlant.L5X"])["WaterPlant.L5X"]["state"] == "DRIFT"
    records.append(
        {"event": {"action": "plc-logic-restored"}, "file": {"name": "WaterPlant.L5X"}, "message": "ok"}
    )
    assert dashboard.file_status(records, ["WaterPlant.L5X"])["WaterPlant.L5X"]["state"] == "OK"


def test_streamlit_app_renders_alerts(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    cfg = setup_demo(tmp_path, monkeypatch)
    log = ledger.Ledger(config.load(cfg).ledger, KEY)
    log.append(drift_record("+<script>alert(1)</script>"))
    monkeypatch.setenv("OTGUARD_CONFIG", cfg)
    monkeypatch.chdir(ROOT)
    app = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=60)
    app.run()
    assert not app.exception
    assert any("1 alert(s) recorded" in e.value for e in app.error)
    assert any("Hash chain and MACs verified" in s.value for s in app.sidebar.success)
    markdown = " ".join(m.value for m in app.markdown)
    assert "&lt;script&gt;" in markdown and "<script>alert(1)" not in markdown
