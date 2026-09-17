"""
Exercises the real L5XParser against real PLC-style XML files on disk -
normalization, signing, and drift detection - plus the fail-closed
behavior when no secret is configured.
"""
import os

import pytest

from engine.parser import L5XParser

BASELINE_XML = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" ExportDate="Mon May 20 15:46:14 2019">
    <Controller>
        <Rung Number="0">
            <Instruction Name="XIC" Operand="Sensor_Temp_High"/>
            <Tag><Data Value="1000"/></Tag>
        </Rung>
    </Controller>
</RSLogix5000Content>
"""

# Same logic, different volatile root-level metadata only (export date) -
# note this deliberately does NOT vary the Data Value attribute: normalize_xml
# only clears element *text* content, not attributes, so a Data tag encoded
# as `<Data Value="X"/>` (exactly how this project's own PLC files store
# values - see plc_config/baseline.xml) is NOT treated as volatile noise by
# the current implementation. See the "Known limitations" note in the README.
BASELINE_XML_DIFFERENT_METADATA = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" ExportDate="Tue Jan 1 00:00:00 2030" Owner="a_different_engineer">
    <Controller>
        <Rung Number="0">
            <Instruction Name="XIC" Operand="Sensor_Temp_High"/>
            <Tag><Data Value="1000"/></Tag>
        </Rung>
    </Controller>
</RSLogix5000Content>
"""

ALTERED_XML = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" ExportDate="Mon May 20 15:46:14 2019">
    <Controller>
        <Rung Number="0">
            <Instruction Name="XIO" Operand="Sensor_Temp_High"/>
            <Tag><Data Value="1000"/></Tag>
        </Rung>
    </Controller>
</RSLogix5000Content>
"""


@pytest.fixture
def parser():
    return L5XParser(secret_key=b"test-secret-not-for-production")


@pytest.fixture
def baseline_file(tmp_path):
    p = tmp_path / "baseline.xml"
    p.write_bytes(BASELINE_XML)
    return str(p)


def test_missing_secret_env_var_raises_instead_of_using_a_default():
    os.environ.pop("OT_GUARD_SECRET_KEY", None)
    with pytest.raises(ValueError, match="OT_GUARD_SECRET_KEY"):
        L5XParser()


def test_secret_from_env_var_is_used_when_no_explicit_key_given(monkeypatch):
    monkeypatch.setenv("OT_GUARD_SECRET_KEY", "from-env")
    parser_from_env = L5XParser()
    assert parser_from_env.secret_key == b"from-env"


def test_normalize_strips_volatile_root_level_attributes(tmp_path, parser):
    a = tmp_path / "a.xml"
    b = tmp_path / "b.xml"
    a.write_bytes(BASELINE_XML)
    b.write_bytes(BASELINE_XML_DIFFERENT_METADATA)

    assert parser.normalize_xml(str(a)) == parser.normalize_xml(str(b))


def test_identical_logic_does_not_drift_even_with_different_metadata(
    tmp_path, parser, baseline_file
):
    signature = parser.sign_baseline(baseline_file)

    other_file = tmp_path / "active.xml"
    other_file.write_bytes(BASELINE_XML_DIFFERENT_METADATA)

    drifted, _, _ = parser.check_drift(str(other_file), signature)
    assert drifted is False


def test_altered_instruction_is_detected_as_drift(tmp_path, parser, baseline_file):
    signature = parser.sign_baseline(baseline_file)

    active_file = tmp_path / "active.xml"
    active_file.write_bytes(ALTERED_XML)

    drifted, current_content, current_signature = parser.check_drift(
        str(active_file), signature
    )
    assert drifted is True
    assert current_signature != signature
    assert "XIO" in current_content


def test_data_value_attribute_changes_are_never_treated_as_volatile_noise(
    tmp_path, parser, baseline_file
):
    """
    Documents a real gap: normalize_xml() only clears element *text*
    content on <Data> tags, never attributes. Every <Data> tag in this
    project's own PLC files (see plc_config/baseline.xml) encodes its
    value as a `Value` attribute, e.g. `<Data Value="1000"/>`, not as
    text. That's exactly why the pressure-threshold attack (also a
    `Value` attribute) is correctly caught as drift - but it also means
    a genuinely volatile field using the same attribute-based encoding
    (e.g. a live scan counter) would falsely trigger an alert on every
    change instead of being filtered out as noise. There's currently no
    way to tell the two apart from the XML shape alone.
    """
    signature = parser.sign_baseline(baseline_file)

    active_file = tmp_path / "active.xml"
    active_file.write_bytes(
        BASELINE_XML.replace(b'Value="1000"', b'Value="1001"')
    )

    drifted, _, _ = parser.check_drift(str(active_file), signature)
    assert drifted is True


def test_malformed_xml_raises_value_error(tmp_path, parser):
    bad_file = tmp_path / "bad.xml"
    bad_file.write_bytes(b"<not><valid xml")

    with pytest.raises(ValueError, match="Invalid XML file"):
        parser.normalize_xml(str(bad_file))
