"""Ladder logic (RLL) rung text: tokenizing and explaining a change.

L5X stores each rung as neutral text, e.g.

    [XIC(Start_PB) ,XIC(Pump_Run) ]XIO(Stop_PB)OTE(Pump_Run);

``[``, ``,`` and ``]`` open, separate and close parallel branches; everything
else is an instruction with operands. Comparing two rungs instruction by
instruction turns "the text changed" into a statement an engineer can act
on, such as "contact on Temp_High inverted (XIC -> XIO)".
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

CONTACTS = {"XIC": "XIO", "XIO": "XIC"}
OUTPUTS = {"OTE", "OTL", "OTU"}
COMPARISONS = {"EQU", "NEQ", "GRT", "GEQ", "LES", "LEQ", "LIM", "MEQ", "CMP"}
TIMERS_COUNTERS = {"TON", "TOF", "RTO", "CTU", "CTD", "TONR", "TOFR", "RTOR", "CTUD"}
FLOW = {"JMP", "JSR", "TND", "MCR", "SBR", "RET", "LBL"}


@dataclass(frozen=True)
class Token:
    name: str  # instruction mnemonic, or "[" "," "]"
    operands: tuple[str, ...] = ()

    def __str__(self) -> str:
        if self.name in "[,]":
            return self.name
        return f"{self.name}({','.join(self.operands)})"


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n;":
            i += 1
        elif ch in "[,]":
            tokens.append(Token(ch))
            i += 1
        else:
            start = i
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
            name = text[start:i]
            if not name:  # unexpected character: keep it as a token rather than loop
                tokens.append(Token(ch))
                i += 1
                continue
            operands: list[str] = []
            if i < n and text[i] == "(":
                depth, current, i = 1, "", i + 1
                while i < n and depth:
                    c = text[i]
                    if c == "(":
                        depth += 1
                    elif c == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    if c == "," and depth == 1:
                        operands.append(current.strip())
                        current = ""
                    else:
                        current += c
                    i += 1
                operands.append(current.strip())
                i += 1  # closing parenthesis
                if operands == [""]:
                    operands = []
            tokens.append(Token(name.upper(), tuple(operands)))
    return tokens


@dataclass(frozen=True)
class Finding:
    severity: str  # MEDIUM | HIGH | CRITICAL
    summary: str


def explain(before: str, after: str) -> list[Finding]:
    """What changed between two versions of one rung, most serious first."""
    old, new = tokenize(before), tokenize(after)
    findings: list[Finding] = []
    matcher = SequenceMatcher(a=[str(t) for t in old], b=[str(t) for t in new], autojunk=False)
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            continue
        removed, added = old[i1:i2], new[j1:j2]
        paired = list(zip(removed, added, strict=False)) if op == "replace" else []
        for a, b in paired:
            findings.extend(_replacement(a, b))
        for token in removed[len(paired) :]:
            findings.extend(_removal(token))
        for token in added[len(paired) :]:
            findings.extend(_addition(token))
    if not findings and before != after:
        findings.append(Finding("HIGH", "rung logic changed"))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    return sorted(findings, key=lambda f: order[f.severity])


def _replacement(a: Token, b: Token) -> list[Finding]:
    if CONTACTS.get(a.name) == b.name and a.operands == b.operands:
        return [Finding("CRITICAL", f"contact on {_op(a)} inverted ({a.name} -> {b.name})")]
    if a.name in OUTPUTS and b.name in OUTPUTS and a.operands == b.operands:
        return [Finding("HIGH", f"output {_op(a)} changed from {a.name} to {b.name}")]
    if a.name in OUTPUTS and a.operands != b.operands:
        return [Finding("CRITICAL", f"output {_op(a)} no longer driven here ({a} -> {b})")]
    if a.name == b.name and a.name in COMPARISONS:
        return [Finding("HIGH", f"comparison changed: {a} -> {b}")]
    if a.name == b.name and a.name in TIMERS_COUNTERS:
        return [Finding("HIGH", f"{a.name} changed: {a} -> {b}")]
    return [*_removal(a), *_addition(b)]


def _removal(token: Token) -> list[Finding]:
    if token.name in "[,]":
        return [Finding("HIGH", "branch structure changed")]
    if token.name in OUTPUTS:
        return [Finding("CRITICAL", f"output instruction removed: {token}")]
    if token.name in CONTACTS or token.name in COMPARISONS:
        return [Finding("CRITICAL", f"condition removed: {token}")]
    return [Finding("HIGH", f"instruction removed: {token}")]


def _addition(token: Token) -> list[Finding]:
    if token.name == "AFI":
        return [Finding("CRITICAL", "AFI (always false) inserted: the rung can never energize")]
    if token.name == "TND":
        return [Finding("CRITICAL", "TND inserted: the rest of the scan is skipped")]
    if token.name in FLOW:
        return [Finding("HIGH", f"program flow instruction inserted: {token}")]
    if token.name in "[,]":
        return [Finding("HIGH", "branch structure changed (a branch can bypass conditions)")]
    if token.name in OUTPUTS:
        return [Finding("HIGH", f"output instruction added: {token}")]
    if token.name == "NOP":
        return [Finding("MEDIUM", "NOP inserted")]
    return [Finding("HIGH", f"instruction added: {token}")]


def _op(token: Token) -> str:
    return token.operands[0] if token.operands else "?"


def has_output(text: str) -> bool:
    return any(token.name in OUTPUTS for token in tokenize(text))
