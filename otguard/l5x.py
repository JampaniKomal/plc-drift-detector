"""Reading Rockwell L5X project exports: separating logic from noise.

An L5X file mixes three kinds of content:

* control logic and configuration: rungs, routines, programs, tasks, tag
  declarations, setpoints. A change here is what OT-Guard must catch;
* export metadata: export date, owner, last-modified stamps. It changes on
  every export and means nothing;
* live values: the export snapshots every tag's current value, so process
  values, I/O states, counters and timer accumulators differ between two
  exports of the same, untouched logic.

The project fingerprint covers the first kind only. Which tag values are
live is project knowledge, so it comes from the policy (glob patterns such
as ``*_PV``). Everything not declared volatile is protected, so an unknown
tag fails safe: its value changes are reported.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

DEFAULT_VOLATILE_ATTRIBUTES = (
    "ExportDate",
    "ExportOptions",
    "Owner",
    "SoftwareRevision",
    "LastModifiedDate",
    "EditedDate",
    "EditedBy",
    "CreatedDate",
    "CreatedBy",
)
# Runtime status members of TIMER, COUNTER and CONTROL structures. Presets
# (.PRE) and lengths (.LEN) are parameters and stay protected.
DEFAULT_VOLATILE_TAGS = (
    "*.ACC",
    "*.EN",
    "*.TT",
    "*.DN",
    "*.CU",
    "*.CD",
    "*.OV",
    "*.UN",
    "*.POS",
    "*.ER",
    "*.IN",
    "*.FD",
    "*.UL",
    "*.EM",
    "*.EU",
)
DOCUMENTATION = (
    "Description",
    "Comment",
    "LocalizedDescription",
    "LocalizedComment",
    "RevisionNote",
    "AdditionalHelpText",
)
MAX_BYTES = 256 * 1024 * 1024
_PROLOG_DOCTYPE = re.compile(rb"(?:\xef\xbb\xbf)?(?:\s+|<\?.*?\?>|<!--.*?-->)*<!DOCTYPE", re.S | re.I)


class ProjectError(ValueError):
    """The file is not a readable L5X project."""


@dataclass(frozen=True)
class Normalization:
    volatile_attributes: tuple[str, ...] = DEFAULT_VOLATILE_ATTRIBUTES
    volatile_tags: tuple[str, ...] = DEFAULT_VOLATILE_TAGS

    def is_volatile(self, key: str) -> bool:
        return any(fnmatch.fnmatchcase(key, pattern) for pattern in self.volatile_tags)


@dataclass(frozen=True)
class Rung:
    number: str
    text: str
    type: str = "N"


@dataclass(frozen=True)
class Routine:
    location: str  # "MainProgram/MainRoutine" or "AOI:Name/Logic"
    type: str
    rungs: tuple[Rung, ...] = ()
    lines: tuple[str, ...] = ()  # Structured Text


@dataclass(frozen=True)
class Tag:
    key: str  # "Name" (controller scope) or "Program/Name"
    data_type: str
    constant: str
    external_access: str
    alias_for: str


@dataclass
class Project:
    path: str
    routines: dict[str, Routine] = field(default_factory=dict)
    tags: dict[str, Tag] = field(default_factory=dict)
    values: dict[str, str] = field(default_factory=dict)  # protected values only
    volatile_values: int = 0
    tasks: dict[str, dict[str, str]] = field(default_factory=dict)
    programs: dict[str, dict[str, str]] = field(default_factory=dict)
    structure: bytes = b""  # canonical XML of the logic, without values or noise
    residual: bytes = b""  # the structure minus everything diff.py explains
    fingerprint: str = ""

    def readable_lines(self) -> list[str]:
        """A line-per-item rendering used for the plain unified diff."""
        lines = etree.tostring(etree.fromstring(self.structure), pretty_print=True).decode().splitlines()
        lines += [f"value {key} = {value}" for key, value in sorted(self.values.items())]
        return lines


def _parse(data: bytes, path: str) -> etree._Element:
    if len(data) > MAX_BYTES:
        raise ProjectError(f"{path}: larger than {MAX_BYTES:,} bytes")
    if _PROLOG_DOCTYPE.match(data):
        raise ProjectError(f"{path}: document type declarations are not accepted")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)
    try:
        root = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as exc:
        raise ProjectError(f"{path}: not well-formed XML ({exc})") from None
    if root.getroottree().docinfo.internalDTD is not None:
        raise ProjectError(f"{path}: document type declarations are not accepted")
    if root.tag != "RSLogix5000Content" or root.find("Controller") is None:
        raise ProjectError(f"{path}: not an L5X project (no RSLogix5000Content/Controller)")
    return root


def load(path: str | Path, normalization: Normalization | None = None) -> Project:
    path = str(path)
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ProjectError(f"{path}: {exc.strerror or exc}") from None
    return loads(data, path, normalization)


def loads(data: bytes, path: str = "<memory>", normalization: Normalization | None = None) -> Project:
    norm = normalization or Normalization()
    root = _parse(data, path)
    project = Project(path=path)

    for routine in root.iter("Routine"):
        location = f"{_owner(routine)}/{routine.get('Name', '?')}"
        kind = routine.get("Type", "")
        rungs = tuple(
            Rung(rung.get("Number", "?"), _text(rung.find("Text")), rung.get("Type", "N"))
            for rung in routine.iterfind("RLLContent/Rung")
        )
        lines = tuple(_text(line) for line in routine.iterfind("STContent/Line"))
        project.routines[location] = Routine(location, kind, rungs, lines)

    for tag in root.iter("Tag"):
        if tag.getparent() is None or tag.getparent().tag != "Tags":
            continue  # <Tag> also appears inside some v1-style rungs; only declarations count
        key = _tag_key(tag)
        project.tags[key] = Tag(
            key,
            tag.get("DataType", ""),
            tag.get("Constant", "false"),
            tag.get("ExternalAccess", ""),
            tag.get("AliasFor", ""),
        )
        for member, value in _tag_values(tag, key).items():
            if norm.is_volatile(member):
                project.volatile_values += 1
            else:
                project.values[member] = value

    # Version 1 sample files kept a value inside the rung: <Rung><Tag><Data Value="1000"/></Tag></Rung>.
    for data in root.xpath("//Rung/Tag/Data[@Value]"):
        rung = data.getparent().getparent()
        owner = rung.getparent().getparent()
        key = f"{_owner(owner)}/{owner.get('Name', '?')}#rung{rung.get('Number', '?')}"
        project.values[key] = data.get("Value")

    for task in root.iterfind("Controller/Tasks/Task"):
        attributes = {k: v for k, v in sorted(task.attrib.items()) if k not in norm.volatile_attributes}
        attributes["ScheduledPrograms"] = ",".join(
            p.get("Name", "") for p in task.iterfind("ScheduledPrograms/ScheduledProgram")
        )
        project.tasks[task.get("Name", "?")] = attributes

    for program in root.iterfind("Controller/Programs/Program"):
        project.programs[program.get("Name", "?")] = {
            k: v for k, v in sorted(program.attrib.items()) if k not in norm.volatile_attributes
        }

    project.structure = _structure(root, norm)
    project.residual = _residual(project.structure)
    digest = hashlib.sha256(project.structure)
    digest.update(b"\0" + json.dumps(project.values, sort_keys=True).encode())
    project.fingerprint = digest.hexdigest()
    return project


def _structure(root: etree._Element, norm: Normalization) -> bytes:
    """Canonical XML (C14N) of the project with values, documentation and metadata removed."""
    tree = deepcopy(root)
    for element in list(tree.iter(etree.Comment, etree.PI)):
        _remove(element)
    for name in DOCUMENTATION:
        for element in list(tree.iter(name)):
            _remove(element)
    for data in list(tree.xpath("//Tag/Data")):
        _remove(data)
    for element in tree.iter():
        for attribute in norm.volatile_attributes:
            element.attrib.pop(attribute, None)
        if element.text is not None:
            element.text = element.text.strip() or None
        if element.tail is not None:
            element.tail = None
    return etree.tostring(tree, method="c14n")


def _residual(structure: bytes) -> bytes:
    """What remains once routines, tag declarations, tasks and program settings are taken out.

    diff.py explains changes in those parts; a change anywhere else (module
    configuration, data types, safety settings...) still shows up here, so no
    change to the fingerprint can go unreported.
    """
    tree = etree.fromstring(structure)
    for name in ("Routine", "Tag", "Task"):
        for element in list(tree.iter(name)):
            _remove(element)
    for program in tree.iter("Program"):
        program.attrib.clear()
    return etree.tostring(tree, method="c14n")


def _remove(element) -> None:
    parent = element.getparent()
    if parent is not None:
        parent.remove(element)


def _text(element) -> str:
    return (element.text or "").strip() if element is not None else ""


def _owner(element) -> str:
    """Name of the program or Add-On Instruction that contains an element."""
    for ancestor in element.iterancestors():
        if ancestor.tag == "Program":
            return ancestor.get("Name", "?")
        if ancestor.tag == "AddOnInstructionDefinition":
            return "AOI:" + ancestor.get("Name", "?")
    return "Controller"


def _tag_key(tag) -> str:
    owner = _owner(tag)
    name = tag.get("Name", "?")
    return name if owner == "Controller" else f"{owner}/{name}"


def _tag_values(tag, key: str) -> dict[str, str]:
    values: dict[str, str] = {}
    decorated = tag.find("Data[@Format='Decorated']")
    if decorated is not None:
        for child in decorated:
            _walk(child, key, values)
        if values:
            return values
    for data in tag.iterfind("Data"):
        if data.get("Format") in (None, "L5K"):
            text = _text(data) or data.get("Value", "")
            if text:
                values[key] = text
                break
    return values


def _walk(element, prefix: str, out: dict[str, str]) -> None:
    kind = element.tag
    if kind in ("DataValue",):
        out[prefix] = element.get("Value", "")
    elif kind == "DataValueMember":
        out[f"{prefix}.{element.get('Name')}"] = element.get("Value", _text(element))
    elif kind in ("Structure", "StructureMember"):
        name = element.get("Name")
        base = f"{prefix}.{name}" if kind == "StructureMember" and name else prefix
        for child in element:
            _walk(child, base, out)
    elif kind in ("Array", "ArrayMember"):
        name = element.get("Name")
        base = f"{prefix}.{name}" if kind == "ArrayMember" and name else prefix
        for child in element:
            _walk(child, base, out)
    elif kind == "Element":
        index = element.get("Index", "")
        if element.get("Value") is not None:
            out[f"{prefix}{index}"] = element.get("Value", "")
        for child in element:
            _walk(child, f"{prefix}{index}", out)
