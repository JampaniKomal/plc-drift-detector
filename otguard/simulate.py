"""Demo attacks on the sample project, and the demo workspace.

Each scenario edits the L5X the way a malicious or careless change would,
using the real L5X structure (rung text in CDATA, values in both the L5K and
the Decorated data blocks). ``benign-export`` changes only noise (export
time stamps, live values, timer accumulators, comments) and must NOT raise
an alert.

``--atomic`` writes a temporary file and renames it over the project, which
is how many editors save. The original engine only listened for in-place
modifications and never saw such a change.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from lxml import etree

SAMPLE = "WaterPlant.L5X"


def _rung(root, number: str):
    return root.find(f".//Routine[@Name='MainRoutine']/RLLContent/Rung[@Number='{number}']")


def _set_rung_text(root, number: str, text: str) -> None:
    _rung(root, number).find("Text").text = etree.CDATA(text)


def _set_value(root, tag: str, l5k: str, decorated: dict[str, str]) -> None:
    element = root.find(f"Controller/Tags/Tag[@Name='{tag}']")
    element.find("Data[@Format='L5K']").text = etree.CDATA(l5k)
    for node in element.find("Data[@Format='Decorated']").iter("DataValue", "DataValueMember"):
        name = node.get("Name", "")
        if name in decorated:
            node.set("Value", decorated[name])


def invert_contact(root) -> str:
    _set_rung_text(root, "0", "XIO(Temp_High)OTE(Cooling_Fan);")
    return "rung 0: the cooling fan now runs only when the motor is NOT hot (XIC -> XIO)"


def raise_setpoint(root) -> str:
    _set_value(root, "High_Pressure_SP", "5000", {"": "5000"})
    return "High_Pressure_SP 1000 -> 5000 kPa: the relief valve opens far too late"


def disable_interlock(root) -> str:
    _set_rung_text(root, "1", "AFI()GRT(Pressure_PV,High_Pressure_SP)OTE(Safety_Valve);")
    return "rung 1: AFI inserted, the relief valve can never open"


def remove_interlock(root) -> str:
    rung = _rung(root, "1")
    rung.getparent().remove(rung)
    for later in root.iterfind(".//Routine[@Name='MainRoutine']/RLLContent/Rung"):
        if int(later.get("Number")) > 1:
            later.set("Number", str(int(later.get("Number")) - 1))
    return "rung 1 (the pressure interlock) deleted"


def shorten_timer(root) -> str:
    _set_value(root, "Valve_Delay", "[0,500,0]", {"PRE": "500"})
    return "Valve_Delay preset 5000 -> 500 ms: the pump may restart almost immediately"


def unlock_setpoint(root) -> str:
    tag = root.find("Controller/Tags/Tag[@Name='High_Pressure_SP']")
    tag.set("Constant", "false")
    tag.set("ExternalAccess", "Read/Write")
    return "High_Pressure_SP no longer Constant and writable from outside the controller"


def inhibit_task(root) -> str:
    root.find("Controller/Tasks/Task[@Name='MainTask']").set("InhibitTask", "true")
    return "MainTask inhibited: none of the logic runs"


def benign_export(root) -> str:
    root.set("ExportDate", "Thu Oct 01 08:00:00 2026")
    root.find("Controller").set("LastModifiedDate", "Thu Oct 01 07:59:12 2026")
    _set_value(root, "Pressure_PV", "731", {"": "731"})
    _set_value(root, "Tank_Level", "5.81250000e+001", {"": "58.125"})
    _set_value(root, "Scan_Counter", "991204", {"": "991204"})
    _set_value(root, "Valve_Delay", "[0,5000,1200]", {"ACC": "1200", "EN": "1", "TT": "1"})
    _rung(root, "3").insert(0, _comment("Relief valve hold-off timer"))
    return "re-exported later: new time stamps, live values, timer accumulator and a comment; no logic change"


def _comment(text: str):
    element = etree.Element("Comment")
    element.text = etree.CDATA(text)
    return element


SCENARIOS: dict[str, Callable] = {
    "invert-contact": invert_contact,
    "raise-setpoint": raise_setpoint,
    "disable-interlock": disable_interlock,
    "remove-interlock": remove_interlock,
    "shorten-timer": shorten_timer,
    "unlock-setpoint": unlock_setpoint,
    "inhibit-task": inhibit_task,
    "benign-export": benign_export,
}


def apply(path: Path, scenario: str, *, atomic: bool = False) -> str:
    parser = etree.XMLParser(strip_cdata=False, resolve_entities=False, no_network=True)
    tree = etree.parse(str(path), parser)
    description = SCENARIOS[scenario](tree.getroot())
    data = etree.tostring(tree, xml_declaration=True, encoding="UTF-8", standalone=True)
    if atomic:
        handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".~", suffix=".tmp")
        with os.fdopen(handle, "wb") as out:
            out.write(data)
        os.replace(temporary, path)
    else:
        path.write_bytes(data)
    return description


DEMO_CONFIG = """# OT-Guard demo configuration (see README)
[engine]
baselines = "baselines"
ledger = "logs/otguard-ledger.jsonl"
rescan_seconds = 10
settle_seconds = 0.5

[normalize]
# Live process values and I/O states in this project; their values change between exports.
volatile_tags = ["*_PV", "Tank_Level", "Scan_Counter", "Temp_High", "Cooling_Fan",
                 "Safety_Valve", "Start_PB", "Stop_PB", "Pump_Run"]

[[watch]]
path = "project/WaterPlant.L5X"
"""


def init_demo(directory: Path, *, force: bool = False) -> Path:
    """Create a demo workspace: the sample project, a config, and nothing approved yet."""
    project = directory / "project" / SAMPLE
    config = directory / "otguard.toml"
    if config.exists() and not force:
        return config
    if force:
        shutil.rmtree(directory / "baselines", ignore_errors=True)
        (directory / "logs" / "otguard-ledger.jsonl").unlink(missing_ok=True)
    project.parent.mkdir(parents=True, exist_ok=True)
    project.write_bytes(resources.files("otguard").joinpath(f"data/{SAMPLE}").read_bytes())
    config.write_text(DEMO_CONFIG, encoding="utf-8")
    return config
