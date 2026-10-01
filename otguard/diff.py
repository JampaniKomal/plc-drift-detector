"""Semantic difference between an approved project and the current one.

Every change gets a location an engineer recognises ("MainProgram/MainRoutine
rung 1"), a plain statement of what changed, a severity, and the ATT&CK for
ICS technique it corresponds to. Anything outside the parts understood here
is still reported, as an unclassified change, so the fingerprint and the
explanation can never disagree silently.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import asdict, dataclass
from functools import cache
from importlib import resources

from . import ladder
from .l5x import Project, Routine

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
ALARM_MEMBERS = (".HHLimit", ".HLimit", ".LLimit", ".LLLimit", ".ROCPosLimit", ".ROCNegLimit", ".Deadband")
ALARM_INSTRUCTIONS = {"ALMA", "ALMD"}


@dataclass(frozen=True)
class Change:
    kind: str
    location: str
    summary: str
    severity: str
    technique: str | None = None
    before: str | None = None
    after: str | None = None

    def as_dict(self) -> dict:
        data = {k: v for k, v in asdict(self).items() if v is not None}
        if self.technique:
            data["technique"] = attack_technique(self.technique)
        return data


@cache
def _attack() -> dict:
    text = resources.files("otguard").joinpath("data/attack_ics.json").read_text(encoding="utf-8")
    return json.loads(text)


def attack_version() -> str:
    return _attack()["attack_ics_version"]


def attack_technique(technique_id: str) -> dict:
    entry = _attack()["techniques"][technique_id]
    return {"id": technique_id, "name": entry["name"], "tactics": entry["tactics"]}


def worst(changes: list[Change]) -> str | None:
    return max((c.severity for c in changes), key=SEVERITY_ORDER.__getitem__, default=None)


def compare(baseline: Project, current: Project) -> list[Change]:
    changes: list[Change] = []
    changes += _routines(baseline, current)
    changes += _programs(baseline, current)
    changes += _tasks(baseline, current)
    changes += _tags(baseline, current)
    changes += _values(baseline, current)
    if baseline.residual != current.residual:
        changes.append(_unclassified(baseline, current))
    return sorted(changes, key=lambda c: -SEVERITY_ORDER[c.severity])


def _rung_technique(*texts: str) -> str:
    tokens = {t.name for text in texts for t in ladder.tokenize(text)}
    return "T0838" if tokens & ALARM_INSTRUCTIONS else "T0889"


def _routines(baseline: Project, current: Project) -> list[Change]:
    changes = []
    for location in sorted(baseline.routines.keys() - current.routines.keys()):
        old = baseline.routines[location]
        outputs = any(ladder.has_output(r.text) for r in old.rungs)
        changes.append(
            Change(
                "routine_removed",
                location,
                f"routine removed ({len(old.rungs)} rungs)" + (", including outputs" if outputs else ""),
                "CRITICAL" if outputs else "HIGH",
                "T0889",
            )
        )
    for location in sorted(current.routines.keys() - baseline.routines.keys()):
        new = current.routines[location]
        changes.append(
            Change(
                "routine_added",
                location,
                f"routine added ({new.type}, {len(new.rungs) or len(new.lines)} rungs/lines)",
                "HIGH",
                "T0889",
                after="\n".join(r.text for r in new.rungs) or "\n".join(new.lines) or None,
            )
        )
    for location in sorted(baseline.routines.keys() & current.routines.keys()):
        changes += _routine(baseline.routines[location], current.routines[location])
    return changes


def _routine(old: Routine, new: Routine) -> list[Change]:
    if old.type != new.type:
        return [
            Change(
                "routine_modified",
                old.location,
                f"routine type changed {old.type} -> {new.type}",
                "HIGH",
                "T0889",
            )
        ]
    changes = []
    if old.lines != new.lines:
        diff = "\n".join(difflib.unified_diff(old.lines, new.lines, lineterm="", n=1))
        changes.append(
            Change("st_modified", old.location, "Structured Text changed", "HIGH", "T0889", after=diff)
        )

    old_texts = [r.text for r in old.rungs]
    new_texts = [r.text for r in new.rungs]
    matcher = difflib.SequenceMatcher(a=old_texts, b=new_texts, autojunk=False)
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            continue
        pairs = list(zip(old.rungs[i1:i2], new.rungs[j1:j2], strict=False)) if op == "replace" else []
        for a, b in pairs:
            findings = ladder.explain(a.text, b.text)
            changes.append(
                Change(
                    "rung_modified",
                    f"{old.location} rung {a.number}",
                    "; ".join(f.summary for f in findings),
                    findings[0].severity,
                    _rung_technique(a.text, b.text),
                    a.text,
                    b.text,
                )
            )
        for rung in old.rungs[i1 + len(pairs) : i2]:
            outputs = ladder.has_output(rung.text)
            changes.append(
                Change(
                    "rung_removed",
                    f"{old.location} rung {rung.number}",
                    "rung removed" + (" (it drove an output)" if outputs else ""),
                    "CRITICAL" if outputs else "HIGH",
                    _rung_technique(rung.text),
                    rung.text,
                    None,
                )
            )
        for rung in new.rungs[j1 + len(pairs) : j2]:
            changes.append(
                Change(
                    "rung_added",
                    f"{new.location} rung {rung.number}",
                    "rung added",
                    "HIGH",
                    _rung_technique(rung.text),
                    None,
                    rung.text,
                )
            )
    return changes


def _programs(baseline: Project, current: Project) -> list[Change]:
    changes = []
    for name in sorted(baseline.programs.keys() - current.programs.keys()):
        changes.append(Change("program_removed", name, "program removed", "CRITICAL", "T0889"))
    for name in sorted(current.programs.keys() - baseline.programs.keys()):
        changes.append(Change("program_added", name, "program added", "HIGH", "T0889"))
    for name in sorted(baseline.programs.keys() & current.programs.keys()):
        old, new = baseline.programs[name], current.programs[name]
        for key in sorted(old.keys() | new.keys()):
            if old.get(key) != new.get(key):
                disabled = key == "Disabled" and new.get(key) == "true"
                changes.append(
                    Change(
                        "program_modified",
                        name,
                        "program disabled" if disabled else f"program setting {key} changed",
                        "CRITICAL" if disabled else "HIGH",
                        "T0889",
                        old.get(key),
                        new.get(key),
                    )
                )
    return changes


def _tasks(baseline: Project, current: Project) -> list[Change]:
    changes = []
    for name in sorted(baseline.tasks.keys() - current.tasks.keys()):
        changes.append(Change("task_removed", name, "task removed", "CRITICAL", "T0821"))
    for name in sorted(current.tasks.keys() - baseline.tasks.keys()):
        changes.append(Change("task_added", name, "task added", "HIGH", "T0821"))
    for name in sorted(baseline.tasks.keys() & current.tasks.keys()):
        old, new = baseline.tasks[name], current.tasks[name]
        for key in sorted(old.keys() | new.keys()):
            if old.get(key) != new.get(key):
                inhibited = key == "InhibitTask" and new.get(key) == "true"
                changes.append(
                    Change(
                        "task_modified",
                        name,
                        "task inhibited: its programs stop running" if inhibited else f"task {key} changed",
                        "CRITICAL" if inhibited else "HIGH",
                        "T0821",
                        old.get(key),
                        new.get(key),
                    )
                )
    return changes


def _tags(baseline: Project, current: Project) -> list[Change]:
    changes = []
    for key in sorted(baseline.tags.keys() - current.tags.keys()):
        changes.append(Change("tag_removed", key, "tag removed", "MEDIUM", "T0889"))
    for key in sorted(current.tags.keys() - baseline.tags.keys()):
        changes.append(
            Change("tag_added", key, f"tag added ({current.tags[key].data_type})", "MEDIUM", "T0889")
        )
    for key in sorted(baseline.tags.keys() & current.tags.keys()):
        old, new = baseline.tags[key], current.tags[key]
        if old.constant != new.constant:
            unlocked = new.constant != "true"
            changes.append(
                Change(
                    "tag_property",
                    key,
                    "Constant flag removed: the value can now be written at run time"
                    if unlocked
                    else "Constant flag set",
                    "HIGH" if unlocked else "MEDIUM",
                    "T0836",
                    old.constant,
                    new.constant,
                )
            )
        if old.external_access != new.external_access:
            opened = new.external_access == "Read/Write"
            changes.append(
                Change(
                    "tag_property",
                    key,
                    "external access widened to Read/Write (HMIs and other devices can write it)"
                    if opened
                    else "external access changed",
                    "HIGH" if opened else "MEDIUM",
                    "T0836",
                    old.external_access,
                    new.external_access,
                )
            )
        if old.data_type != new.data_type:
            changes.append(
                Change(
                    "tag_property", key, "data type changed", "HIGH", "T0889", old.data_type, new.data_type
                )
            )
        if old.alias_for != new.alias_for:
            changes.append(
                Change(
                    "tag_property",
                    key,
                    "alias now points to a different tag or I/O point",
                    "HIGH",
                    "T0836",
                    old.alias_for,
                    new.alias_for,
                )
            )
    return changes


def _values(baseline: Project, current: Project) -> list[Change]:
    changes = []
    for key in sorted(baseline.values.keys() | current.values.keys()):
        old, new = baseline.values.get(key), current.values.get(key)
        if old == new or old is None or new is None:
            continue  # a value appearing or vanishing comes with a tag change reported above
        tag = current.tags.get(key.split(".")[0].split("[")[0])
        constant = tag is not None and tag.constant == "true"
        alarm = key.endswith(ALARM_MEMBERS) or (tag is not None and tag.data_type.startswith("ALARM"))
        what = "alarm limit" if alarm else ("constant" if constant else "protected value")
        changes.append(
            Change(
                "tag_value",
                key,
                f"{what} changed",
                "CRITICAL" if constant or alarm else "HIGH",
                "T0838" if alarm else "T0836",
                old,
                new,
            )
        )
    return changes


def _unclassified(baseline: Project, current: Project) -> Change:
    from lxml import etree

    def lines(residual: bytes) -> list[str]:
        return etree.tostring(etree.fromstring(residual), pretty_print=True).decode().splitlines()

    diff = list(difflib.unified_diff(lines(baseline.residual), lines(current.residual), lineterm="", n=1))
    return Change(
        "unclassified",
        "project",
        "configuration changed outside rungs, tags and tasks (for example modules or data types)",
        "HIGH",
        None,
        after="\n".join(diff[2:60]),
    )


def unified_diff(baseline: Project, current: Project) -> str:
    return "\n".join(
        difflib.unified_diff(
            baseline.readable_lines(),
            current.readable_lines(),
            fromfile="approved",
            tofile="current",
            lineterm="",
        )
    )
