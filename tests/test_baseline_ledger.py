import json

import pytest
from conftest import KEY

from otguard import baseline, config, l5x, ledger


def approve(cfg, path, key=KEY):
    return baseline.approve(cfg, path, key, by="J. Komal", reason="WO-1042 initial")


def test_approve_and_verify(workspace, project_file):
    manifest = approve(workspace, project_file)
    project, loaded = baseline.load_verified(workspace, project_file, KEY)
    assert loaded == manifest
    assert project.fingerprint == manifest["fingerprint"]
    assert manifest["approved_by"] == "J. Komal" and manifest["policy_sha256"] == workspace.policy_sha256


def test_approval_needs_a_name_and_a_reason(workspace, project_file):
    with pytest.raises(baseline.BaselineError, match="reason"):
        baseline.approve(workspace, project_file, KEY, by="x", reason=" ")


def test_an_unreadable_file_cannot_be_approved(workspace, project_file):
    project_file.write_bytes(b"<garbage")
    with pytest.raises(l5x.ProjectError):
        approve(workspace, project_file)


def test_edited_manifest_is_detected(workspace, project_file):
    approve(workspace, project_file)
    _, manifest_path = baseline.paths(workspace, project_file)
    manifest = json.loads(manifest_path.read_text())
    manifest["approved_by"] = "someone else"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(baseline.BaselineError, match="signature is invalid"):
        baseline.load_verified(workspace, project_file, KEY)


def test_tampered_baseline_copy_is_detected(workspace, project_file):
    approve(workspace, project_file)
    copy, _ = baseline.paths(workspace, project_file)
    copy.write_bytes(copy.read_bytes().replace(b"<![CDATA[1000]]>", b"<![CDATA[5000]]>"))
    with pytest.raises(baseline.BaselineError, match="tampered"):
        baseline.load_verified(workspace, project_file, KEY)


def test_another_key_cannot_vouch_for_a_baseline(workspace, project_file):
    approve(workspace, project_file)
    with pytest.raises(baseline.BaselineError, match="signature"):
        baseline.load_verified(workspace, project_file, b"another-key-0123456789")


def test_changing_the_policy_requires_a_new_approval(workspace, project_file):
    approve(workspace, project_file)
    text = workspace.path.read_text().replace('"Scan_Counter", ', "")
    workspace.path.write_text(text)
    with pytest.raises(baseline.BaselineError, match="policy changed"):
        baseline.load_verified(config.load(workspace.path), project_file, KEY)


def test_missing_baseline(workspace, project_file):
    with pytest.raises(baseline.BaselineError, match="no approved baseline"):
        baseline.load_verified(workspace, project_file, KEY)


def test_secret_key_fails_closed(monkeypatch):
    monkeypatch.delenv(config.KEY_ENV, raising=False)
    with pytest.raises(config.ConfigError, match="OT_GUARD_SECRET_KEY"):
        config.secret_key()
    assert config.secret_key(required=False) is None
    monkeypatch.setenv(config.KEY_ENV, "short")
    with pytest.raises(config.ConfigError, match="too short"):
        config.secret_key()


# --- ledger -------------------------------------------------------------------


def write_three(path):
    log = ledger.Ledger(path, KEY)
    for n in range(3):
        log.append({"message": f"event {n}"})
    return path


def test_ledger_chain_verifies_and_continues_after_reopen(tmp_path):
    path = write_three(tmp_path / "l.jsonl")
    ledger.Ledger(path, KEY).append({"message": "after restart"})
    records = list(ledger.read(path))
    assert [r["seq"] for r in records] == [1, 2, 3, 4]
    assert records[1]["prev"] == records[0]["mac"]
    assert ledger.verify(path, KEY) == []


def test_editing_a_record_breaks_its_mac(tmp_path):
    path = write_three(tmp_path / "l.jsonl")
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace("event 1", "nothing to see")
    path.write_text("\n".join(lines) + "\n")
    assert ledger.verify(path, KEY) == ["record 2: MAC does not match (edited, or another key)"]
    assert ledger.verify(path, None) == []  # without the key only the linkage can be checked


def test_deleting_a_record_breaks_the_chain(tmp_path):
    path = write_three(tmp_path / "l.jsonl")
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    problems = ledger.verify(path, None)
    assert "record 3: expected sequence number 2" in problems
    assert "record 3: does not link to the previous record" in problems


def test_garbage_lines_are_reported(tmp_path):
    path = write_three(tmp_path / "l.jsonl")
    with open(path, "a") as handle:
        handle.write("not json\n")
    assert ledger.verify(path, KEY) == ["line 4: not a JSON record"]
