"""Data for the Streamlit dashboard (ui/app.py), kept here so it can be tested."""

from __future__ import annotations

import html

FILE_ACTIONS = {
    "plc-logic-drift": "DRIFT",
    "plc-project-unreadable": "UNREADABLE",
    "plc-project-missing": "MISSING",
    "baseline-invalid": "BASELINE INVALID",
    "plc-logic-restored": "OK",
    "baseline-approved": "OK",
}


def action(record: dict) -> str:
    return record.get("event", {}).get("action", "")


def file_status(records: list[dict], watched: list[str]) -> dict[str, dict]:
    """Latest state of each watched file, from the ledger alone."""
    status = {name: {"state": "OK", "since": None, "message": "no alerts recorded"} for name in watched}
    for record in records:
        name = record.get("file", {}).get("name")
        if action(record) == "engine-started":
            for file_name, info in record.get("otguard", {}).get("baselines", {}).items():
                status.setdefault(file_name, {"state": "OK", "since": None, "message": ""})
                status[file_name]["baseline"] = info
            continue
        if name is None or action(record) not in FILE_ACTIONS:
            continue
        entry = status.setdefault(name, {})
        entry.update(
            state=FILE_ACTIONS[action(record)],
            since=record.get("@timestamp"),
            message=record.get("message", ""),
        )
        if action(record) == "baseline-approved":
            entry["baseline"] = record.get("otguard", {}).get("baseline", {})
    return status


def alerts(records: list[dict]) -> list[dict]:
    return [r for r in reversed(records) if r.get("event", {}).get("kind") == "alert"]


def change_rows(record: dict) -> list[dict]:
    rows = []
    for change in record.get("otguard", {}).get("changes", []):
        technique = change.get("technique") or {}
        rows.append(
            {
                "Severity": change.get("severity"),
                "Where": change.get("location"),
                "What changed": change.get("summary"),
                "Before": change.get("before", ""),
                "After": change.get("after", ""),
                "ATT&CK for ICS": f"{technique.get('id')} {technique.get('name')}" if technique else "",
            }
        )
    return rows


def diff_html(text: str) -> str:
    """Unified diff as coloured HTML. The text comes from the monitored file,
    which an attacker controls, so every line is escaped."""
    out = []
    for line in text.splitlines():
        escaped = html.escape(line)
        if line.startswith("+") and not line.startswith("+++"):
            css = "diff-add"
        elif line.startswith("-") and not line.startswith("---"):
            css = "diff-remove"
        else:
            css = "diff-neutral"
        out.append(f'<div class="{css}">{escaped or "&nbsp;"}</div>')
    return f"<div class='diff-container'>{''.join(out)}</div>"
