import pytest

from otguard import ladder


def test_tokenize_branches_and_nested_operands():
    tokens = ladder.tokenize("[XIC(Start_PB) ,XIC(Pump_Run) ]XIO(Stop_PB)CPT(Out,(A+B)*2)OTE(Pump_Run);")
    assert [str(t) for t in tokens] == [
        "[",
        "XIC(Start_PB)",
        ",",
        "XIC(Pump_Run)",
        "]",
        "XIO(Stop_PB)",
        "CPT(Out,(A+B)*2)",
        "OTE(Pump_Run)",
    ]
    assert ladder.tokenize("TON(Valve_Delay,?,?);")[0].operands == ("Valve_Delay", "?", "?")
    assert ladder.tokenize("AFI()NOP();")[0].operands == ()


@pytest.mark.parametrize(
    "before, after, severity, phrase",
    [
        ("XIC(A)OTE(B);", "XIO(A)OTE(B);", "CRITICAL", "contact on A inverted (XIC -> XIO)"),
        ("XIC(A)OTE(B);", "AFI()XIC(A)OTE(B);", "CRITICAL", "AFI (always false) inserted"),
        ("XIC(A)OTE(B);", "XIC(A)OTE(B)TND();", "CRITICAL", "TND inserted"),
        ("XIC(A)OTE(B);", "XIC(A);", "CRITICAL", "output instruction removed: OTE(B)"),
        ("XIC(A)OTE(B);", "XIC(A)OTE(C);", "CRITICAL", "output B no longer driven here"),
        ("XIC(A)OTE(B);", "XIC(A)OTL(B);", "HIGH", "output B changed from OTE to OTL"),
        ("GRT(P,SP)OTE(V);", "GRT(P,9999)OTE(V);", "HIGH", "comparison changed: GRT(P,SP) -> GRT(P,9999)"),
        ("XIC(A)XIC(Interlock)OTE(B);", "XIC(A)OTE(B);", "CRITICAL", "condition removed: XIC(Interlock)"),
        ("XIC(A)OTE(B);", "[XIC(A) ,XIC(Bypass) ]OTE(B);", "HIGH", "branch structure changed"),
        ("XIC(A)OTE(B);", "XIC(A)JMP(L1)OTE(B);", "HIGH", "program flow instruction inserted: JMP(L1)"),
    ],
)
def test_explain(before, after, severity, phrase):
    findings = ladder.explain(before, after)
    assert findings[0].severity == severity
    assert any(phrase in f.summary for f in findings), findings


def test_has_output():
    assert ladder.has_output("XIC(A)OTL(B);")
    assert not ladder.has_output("XIC(A)TON(T,?,?);")
