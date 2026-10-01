"""The drift engine.

Rules it keeps:

* It never writes to a watched file and never changes a baseline. A detected
  change stays a change until a person approves it (``otguard approve``).
* It checks every watched file at start-up, so tampering done while it was
  stopped is reported.
* It reacts to every way a file can change: in-place writes, atomic saves
  (write a temporary file, then rename it over the original), deletion and
  re-creation. A periodic full re-check covers events the operating system
  never delivers (network shares, some container bind mounts).
* A file that cannot be parsed is reported, not skipped.
* The same drift is reported once; a return to the approved state is
  recorded as well.
"""

from __future__ import annotations

import queue
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import baseline, diff, l5x
from .config import Config
from .ledger import Ledger

ECS_SEVERITY = {"CRITICAL": 99, "HIGH": 73, "MEDIUM": 47, "LOW": 21}
MAX_DIFF_CHARS = 20000
WATCHED_EVENTS = {"created", "modified", "moved", "deleted", "closed"}


class Engine:
    def __init__(self, config: Config, key: bytes, *, ledger: Ledger | None = None, log=print):
        self.config = config
        self.key = key
        self.ledger = ledger or Ledger(config.ledger, key)
        self.log = log
        self.approved: dict[Path, tuple[l5x.Project, dict]] = {}
        self.state: dict[Path, str] = {}
        self._queue: queue.Queue[Path] = queue.Queue()
        self._stop = threading.Event()

    # -- start-up -----------------------------------------------------------

    def start(self) -> bool:
        """Verify every baseline, then check every watched file. False if a baseline is bad."""
        ok = True
        for path in self.config.watched:
            try:
                self.approved[path] = baseline.load_verified(self.config, path, self.key)
            except (baseline.BaselineError, l5x.ProjectError) as exc:
                ok = False
                self._record(
                    "alert",
                    "baseline-invalid",
                    "CRITICAL",
                    path,
                    f"{path.name}: refusing to monitor against an untrusted baseline: {exc}",
                    {"error": str(exc)},
                )
        if not ok:
            return False
        self._record(
            "event",
            "engine-started",
            "LOW",
            None,
            f"monitoring {len(self.config.watched)} file(s)",
            {
                "watched": [str(p) for p in self.config.watched],
                "attack_ics_version": diff.attack_version(),
                "baselines": {
                    p.name: {k: m[k] for k in ("approved_by", "approved_at", "reason", "fingerprint")}
                    for p, (_, m) in self.approved.items()
                },
            },
        )
        for path in self.config.watched:
            self.check(path)
        return True

    # -- checking -------------------------------------------------------------

    def check(self, path: Path) -> dict | None:
        """Compare one watched file with its approved baseline; record what is new."""
        approved, manifest = self.approved[path]
        previous = self.state.get(path)

        if not path.exists():
            self.state[path] = "missing"
            if previous != "missing":
                return self._record(
                    "alert",
                    "plc-project-missing",
                    "HIGH",
                    path,
                    f"{path.name}: watched project file is gone",
                    {},
                )
            return None

        current, error = None, None
        for attempt in range(3):
            try:
                current = l5x.load(path, self.config.normalization)
                break
            except l5x.ProjectError as exc:
                error = exc
                if attempt < 2:
                    time.sleep(self.config.settle_seconds)
        if current is None:
            self.state[path] = "unreadable"
            if previous != "unreadable":
                return self._record(
                    "alert",
                    "plc-project-unreadable",
                    "HIGH",
                    path,
                    f"{path.name}: project file cannot be read as L5X; treat as tampering until explained",
                    {"error": str(error)},
                )
            return None

        if current.fingerprint == approved.fingerprint:
            self.state[path] = approved.fingerprint
            if previous is not None and previous != approved.fingerprint:
                return self._record(
                    "event",
                    "plc-logic-restored",
                    "LOW",
                    path,
                    f"{path.name}: matches the approved baseline again",
                    {"fingerprint": {"approved": approved.fingerprint, "current": current.fingerprint}},
                )
            return None

        if previous == current.fingerprint:
            return None  # this exact drift was already reported
        self.state[path] = current.fingerprint
        changes = diff.compare(approved, current)
        worst = diff.worst(changes) or "HIGH"
        headline = changes[0].summary if changes else "content changed"
        unified = diff.unified_diff(approved, current)
        return self._record(
            "alert",
            "plc-logic-drift",
            worst,
            path,
            f"{path.name}: {len(changes)} unapproved change(s); most serious: {headline}",
            {
                "fingerprint": {"approved": approved.fingerprint, "current": current.fingerprint},
                "baseline": {k: manifest[k] for k in ("approved_by", "approved_at", "reason")},
                "changes": [c.as_dict() for c in changes],
                "diff": unified[:MAX_DIFF_CHARS],
            },
            techniques=[c.technique for c in changes if c.technique],
        )

    def check_all(self) -> None:
        for path in self.config.watched:
            self.check(path)

    # -- running --------------------------------------------------------------

    def notify(self, raw_path: str) -> None:
        try:
            path = Path(raw_path).resolve()
        except OSError:
            return
        if path in self.approved:
            self._queue.put(path)

    def run(self) -> None:
        observer = Observer()
        handler = _Handler(self)
        for directory in sorted({p.parent for p in self.config.watched}):
            observer.schedule(handler, str(directory), recursive=False)
        observer.start()
        self.log(f"[*] watching {', '.join(str(p) for p in self.config.watched)}")
        last_scan = time.monotonic()
        try:
            while not self._stop.is_set():
                try:
                    first = self._queue.get(timeout=0.5)
                except queue.Empty:
                    first = None
                if first is not None:
                    time.sleep(self.config.settle_seconds)  # let the writer finish
                    pending = {first}
                    while not self._queue.empty():
                        pending.add(self._queue.get_nowait())
                    for path in sorted(pending):
                        self.check(path)
                if time.monotonic() - last_scan >= self.config.rescan_seconds:
                    self.check_all()
                    last_scan = time.monotonic()
        finally:
            observer.stop()
            observer.join()

    def stop(self) -> None:
        self._stop.set()

    # -- recording ------------------------------------------------------------

    def _record(self, kind, action, severity, path, message, details, techniques=()) -> dict:
        event = {
            "event": {
                "kind": kind,
                "category": ["configuration"],
                "type": ["change"] if kind == "alert" else ["info"],
                "action": action,
                "module": "otguard",
                "severity": ECS_SEVERITY[severity],
            },
            "log": {"level": severity.lower()},
            "message": message,
            "otguard": {"severity": severity, **details},
        }
        if path is not None:
            event["file"] = {"path": str(path), "name": path.name}
        unique = list(dict.fromkeys(techniques))
        if unique:
            entries = [diff.attack_technique(t) for t in unique]
            tactics = {t["id"]: t for e in entries for t in e["tactics"]}
            event["threat"] = {
                "framework": "MITRE ATT&CK for ICS",
                "technique": [{"id": e["id"], "name": e["name"]} for e in entries],
                "tactic": list(tactics.values()),
            }
        record = self.ledger.append(event)
        prefix = "[!]" if kind == "alert" else "[*]"
        self.log(f"{prefix} {severity} {message}")
        return record


class _Handler(FileSystemEventHandler):
    def __init__(self, engine: Engine):
        self.engine = engine

    def on_any_event(self, event) -> None:
        if event.is_directory or event.event_type not in WATCHED_EVENTS:
            return
        self.engine.notify(event.src_path)
        dest = getattr(event, "dest_path", "")
        if dest:
            self.engine.notify(dest)
