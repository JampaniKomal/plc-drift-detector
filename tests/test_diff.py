import json
from importlib import resources

import pytest
from conftest import edit, sample_bytes
from test_l5x import DEMO_NORMALIZATION

from otguard import diff, l5x, simulate


def changes_for(scenario, tmp_path):
    path = tmp_path / "p.L5X"
    path.write_bytes(sample_bytes())
    before = l5x.load(path, DEMO_NORMALIZATION)
    simulate.apply(path, scenario)
    return diff.compare(before, l5x.load(path, DEMO_NORMALIZATION))


@pytest.mark.parametrize(
    "scenario, kind, location, severity, technique",
    [
        ("invert-contact", "rung_modified", "MainProgram/MainRoutine rung 0", "CRITICAL", "T0889"),
        ("raise-setpoint", "tag_value", "High_Pressure_SP", "CRITICAL", "T0836"),
        ("disable-interlock", "rung_modified", "MainProgram/MainRoutine rung 1", "CRITICAL", "T0889"),
        ("remove-interlock", "rung_removed", "MainProgram/MainRoutine rung 1", "CRITICAL", "T0889"),
        ("shorten-timer", "tag_value", "Valve_Delay.PRE", "HIGH", "T0836"),
        ("unlock-setpoint", "tag_property", "High_Pressure_SP", "HIGH", "T0836"),
        ("inhibit-task", "task_modified", "MainTask", "CRITICAL", "T0821"),
    ],
)
def test_every_attack_scenario_is_explained(tmp_path, scenario, kind, location, severity, technique):
    changes = changes_for(scenario, tmp_path)
    first = changes[0]
    assert (first.kind, first.location, first.severity, first.technique) == (
        kind,
        location,
        severity,
        technique,
    )


def test_benign_export_produces_no_changes(tmp_path):
    assert changes_for("benign-export", tmp_path) == []


def test_deleting_a_rung_does_not_flag_the_renumbered_rungs(tmp_path):
    changes = changes_for("remove-interlock", tmp_path)
    assert [c.kind for c in changes] == ["rung_removed"]


def test_changes_outside_the_known_parts_are_still_reported():
    def change_module(root):
        root.find(".//Module").set("Inhibited", "true")

    changes = diff.compare(l5x.loads(sample_bytes()), l5x.loads(edit(sample_bytes(), change_module)))
    assert [c.kind for c in changes] == ["unclassified"]
    assert 'Inhibited="true"' in changes[0].after


def test_program_disabled_and_routine_added():
    def tamper(root):
        program = root.find("Controller/Programs/Program")
        program.set("Disabled", "true")
        routine = program.find("Routines/Routine").__copy__()
        routine.set("Name", "Backdoor")
        program.find("Routines").append(routine)

    changes = diff.compare(l5x.loads(sample_bytes()), l5x.loads(edit(sample_bytes(), tamper)))
    summary = {(c.kind, c.summary) for c in changes}
    assert ("program_modified", "program disabled") in summary
    assert any(kind == "routine_added" for kind, _ in summary)
    assert changes[0].severity == "CRITICAL"


def test_alarm_limits_map_to_modify_alarm_settings():
    def add_alarm(root):
        tag = root.find("Controller/Tags/Tag[@Name='Valve_Delay']").__copy__()
        tag.set("Name", "Pressure_Alarm")
        tag.set("DataType", "ALARM_ANALOG")
        member = tag.find("Data[@Format='Decorated']/Structure/DataValueMember[@Name='PRE']")
        member.set("Name", "HHLimit")
        root.find("Controller/Tags").append(tag)

    base = edit(sample_bytes(), add_alarm)
    raised = base.replace(
        b'Name="HHLimit" DataType="DINT" Radix="Decimal" Value="5000"',
        b'Name="HHLimit" DataType="DINT" Radix="Decimal" Value="9000"',
    )
    changes = diff.compare(l5x.loads(base), l5x.loads(raised))
    assert [(c.location, c.technique) for c in changes] == [("Pressure_Alarm.HHLimit", "T0838")]


def test_structured_text_routines_are_compared():
    def st_routine(root):
        routine = root.find(".//Routine")
        routine.set("Type", "ST")
        content = routine.find("RLLContent")
        routine.remove(content)
        st = routine.makeelement("STContent", {})
        for number, text in enumerate(
            ["IF Pressure_PV > High_Pressure_SP THEN", "Safety_Valve := 1;", "END_IF;"]
        ):
            line = st.makeelement("Line", {"Number": str(number)})
            line.text = text
            st.append(line)
        routine.append(st)

    base = edit(sample_bytes(), st_routine)
    changed = base.replace(b"Safety_Valve := 1;", b"Safety_Valve := 0;")
    changes = diff.compare(l5x.loads(base), l5x.loads(changed))
    assert [(c.kind, c.technique) for c in changes] == [("st_modified", "T0889")]
    assert "+Safety_Valve := 0;" in changes[0].after


def test_attack_table_is_current_and_has_no_deprecated_techniques():
    data = json.loads(resources.files("otguard").joinpath("data/attack_ics.json").read_text())
    assert data["attack_ics_version"] == "19.2"
    assert "T0833" not in data["techniques"]  # Modify Control Logic, deprecated in ATT&CK for ICS
    assert diff.attack_technique("T0889")["name"] == "Modify Program"
    assert diff.attack_technique("T0836")["tactics"] == [{"id": "TA0106", "name": "Impair Process Control"}]
