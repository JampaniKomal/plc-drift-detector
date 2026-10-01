import pytest
from conftest import edit, sample_bytes

from otguard import l5x, simulate

DEMO_NORMALIZATION = l5x.Normalization(
    l5x.DEFAULT_VOLATILE_ATTRIBUTES,
    (*l5x.DEFAULT_VOLATILE_TAGS, "*_PV", "Tank_Level", "Scan_Counter"),
)


def test_sample_project_model():
    project = l5x.loads(sample_bytes(), "sample", DEMO_NORMALIZATION)
    routine = project.routines["MainProgram/MainRoutine"]
    assert routine.type == "RLL"
    assert [r.number for r in routine.rungs] == ["0", "1", "2", "3", "4"]
    assert routine.rungs[0].text == "XIC(Temp_High)OTE(Cooling_Fan);"
    assert project.tags["High_Pressure_SP"].constant == "true"
    assert project.values["High_Pressure_SP"] == "1000"
    assert project.values["Valve_Delay.PRE"] == "5000"
    assert "Valve_Delay.ACC" not in project.values  # timer accumulator: runtime state
    assert "Pressure_PV" not in project.values and "Scan_Counter" not in project.values
    assert project.tasks["MainTask"]["Type"] == "CONTINUOUS"
    assert project.tasks["MainTask"]["ScheduledPrograms"] == "MainProgram"


def test_a_re_export_with_new_noise_has_the_same_fingerprint(tmp_path):
    path = tmp_path / "p.L5X"
    path.write_bytes(sample_bytes())
    before = l5x.load(path, DEMO_NORMALIZATION)
    simulate.apply(path, "benign-export")
    after = l5x.load(path, DEMO_NORMALIZATION)
    assert before.fingerprint == after.fingerprint


def test_without_a_policy_live_values_count_as_changes(tmp_path):
    """Fail safe: a value nobody declared volatile is protected."""
    path = tmp_path / "p.L5X"
    path.write_bytes(sample_bytes())
    before = l5x.load(path)
    simulate.apply(path, "benign-export")
    assert l5x.load(path).fingerprint != before.fingerprint


def test_comments_and_descriptions_are_not_logic():
    def recomment(root):
        for comment in root.iter("Comment", "Description"):
            comment.text = "edited documentation"

    a = l5x.loads(sample_bytes())
    b = l5x.loads(edit(sample_bytes(), recomment))
    assert a.fingerprint == b.fingerprint


def test_l5k_only_values_are_protected():
    """v1 cleared the text of every Tag/Data element, so values stored only in
    L5K form (no Decorated block) were never compared at all."""

    def l5k_only(root):
        for data in root.iter("Data"):
            if data.get("Format") == "Decorated":
                data.getparent().remove(data)

    base = edit(sample_bytes(), l5k_only)
    raised = base.replace(b"<![CDATA[1000]]>", b"<![CDATA[5000]]>")
    assert l5x.loads(base).values["High_Pressure_SP"] == "1000"
    assert l5x.loads(base).fingerprint != l5x.loads(raised).fingerprint


def test_program_scope_tags_are_keyed_by_program():
    def add_program_tag(root):
        tags = root.find("Controller/Programs/Program/Tags")
        tag = root.find("Controller/Tags/Tag[@Name='High_Pressure_SP']").__copy__()
        tag.set("Name", "Local_SP")
        tags.append(tag)

    project = l5x.loads(edit(sample_bytes(), add_program_tag))
    assert "MainProgram/Local_SP" in project.tags
    assert project.values["MainProgram/Local_SP"] == "1000"


def test_version_1_style_files_still_load():
    v1 = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" ExportDate="Mon May 20 15:46:14 2019"><Controller><Programs><Program Name="P">
<Routines><Routine Name="R"><RLLContent><Rung Number="1"><Text><![CDATA[EQU(Pressure, 1000) OTE(Safety_Valve);]]></Text>
<Tag><Data Value="1000"/></Tag></Rung></RLLContent></Routine></Routines></Program></Programs></Controller></RSLogix5000Content>"""
    project = l5x.loads(v1)
    assert project.values == {"P/R#rung1": "1000"}
    assert l5x.loads(v1.replace(b'Value="1000"', b'Value="5000"')).fingerprint != project.fingerprint


@pytest.mark.parametrize(
    "data, message",
    [
        (b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><RSLogix5000Content/>', "document type"),
        (b"<RSLogix5000Content><Controller>", "not well-formed"),
        (b"<project/>", "not an L5X project"),
    ],
)
def test_unusable_files_are_errors(data, message):
    with pytest.raises(l5x.ProjectError, match=message):
        l5x.loads(data)
