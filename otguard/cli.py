"""otguard command line."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from pathlib import Path

from . import __version__, baseline, config, diff, l5x, ledger, simulate
from .monitor import Engine

DEFAULT_CONFIG = os.environ.get("OTGUARD_CONFIG", "otguard.toml")


def _config(args) -> config.Config:
    return config.load(args.config)


def _watched(cfg: config.Config, name: str | None) -> list[Path]:
    if not name:
        return list(cfg.watched)
    matches = [p for p in cfg.watched if p.name == Path(name).name]
    if not matches:
        raise config.ConfigError(f"{name} is not a watched file in {cfg.path}")
    return matches


def _print_changes(changes: list[diff.Change]) -> None:
    for change in changes:
        technique = ""
        if change.technique:
            entry = diff.attack_technique(change.technique)
            technique = f"  [{entry['id']} {entry['name']}]"
        print(f"  {change.severity:<8} {change.location}: {change.summary}{technique}")
        if change.before is not None or change.after is not None:
            print(f"           before: {change.before}")
            print(f"           after:  {change.after}")


def cmd_approve(args) -> int:
    cfg = _config(args)
    key = config.secret_key()
    log = ledger.Ledger(cfg.ledger, key)
    for path in _watched(cfg, args.file):
        previous = None
        try:
            previous, _ = baseline.load_verified(cfg, path, key)
        except baseline.BaselineError:
            pass
        manifest = baseline.approve(cfg, path, key, by=args.by, reason=args.reason)
        changes = []
        if previous is not None:
            changes = diff.compare(previous, l5x.load(path, cfg.normalization))
        log.append(
            {
                "event": {
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["change"],
                    "action": "baseline-approved",
                    "module": "otguard",
                    "severity": 21,
                },
                "log": {"level": "low"},
                "message": (
                    f"{path.name}: new baseline approved by {manifest['approved_by']}: {manifest['reason']}"
                ),
                "file": {"path": str(path), "name": path.name},
                "otguard": {
                    "severity": "LOW",
                    "baseline": {
                        k: manifest[k] for k in ("approved_by", "approved_at", "reason", "fingerprint")
                    },
                    "changes": [c.as_dict() for c in changes],
                },
            }
        )
        print(f"approved {path.name} ({manifest['fingerprint'][:16]}...) by {manifest['approved_by']}")
        if changes:
            print(f"{len(changes)} change(s) relative to the previous baseline were approved:")
            _print_changes(changes)
    return 0


def cmd_check(args) -> int:
    cfg = _config(args)
    key = config.secret_key()
    drifted = False
    results = []
    for path in _watched(cfg, args.file):
        approved, _ = baseline.load_verified(cfg, path, key)
        try:
            current = l5x.load(path, cfg.normalization)
        except l5x.ProjectError as exc:
            drifted = True
            results.append({"file": str(path), "status": "unreadable", "error": str(exc)})
            if not args.json:
                print(f"{path.name}: UNREADABLE: {exc}")
            continue
        changes = diff.compare(approved, current) if current.fingerprint != approved.fingerprint else []
        drifted |= bool(changes) or current.fingerprint != approved.fingerprint
        results.append(
            {
                "file": str(path),
                "status": "drift" if changes else "ok",
                "changes": [c.as_dict() for c in changes],
            }
        )
        if not args.json:
            if changes:
                print(f"{path.name}: DRIFT, {len(changes)} change(s):")
                _print_changes(changes)
            else:
                print(f"{path.name}: matches the approved baseline")
    if args.json:
        print(json.dumps(results, indent=2))
    return 1 if drifted else 0


def cmd_diff(args) -> int:
    cfg = config.load(args.config) if args.config and Path(args.config).exists() else None
    norm = cfg.normalization if cfg else l5x.Normalization()
    before, after = l5x.load(args.approved, norm), l5x.load(args.current, norm)
    changes = diff.compare(before, after)
    if args.json:
        print(json.dumps([c.as_dict() for c in changes], indent=2))
    elif changes:
        print(f"{len(changes)} change(s):")
        _print_changes(changes)
    else:
        print(
            "no logic changes" + (" (only noise differs)" if before.fingerprint == after.fingerprint else "")
        )
    return 1 if changes else 0


def cmd_watch(args) -> int:
    cfg = _config(args)
    engine = Engine(cfg, config.secret_key())
    if not engine.start():
        return 2
    signal.signal(signal.SIGTERM, lambda *_: engine.stop())
    try:
        engine.run()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_verify_ledger(args) -> int:
    path = Path(args.ledger) if args.ledger else _config(args).ledger
    problems = ledger.verify(path, config.secret_key())
    count = sum(1 for _ in ledger.read(path))
    for problem in problems:
        print(problem)
    print(
        f"{path}: {count} record(s), " + ("chain intact" if not problems else f"{len(problems)} problem(s)")
    )
    return 1 if problems else 0


def cmd_demo_init(args) -> int:
    path = simulate.init_demo(Path(args.dir), force=args.force)
    print(f"demo workspace: {path.parent}")
    if not args.approve:
        print(
            f"next: OT_GUARD_SECRET_KEY=... otguard --config {path} "
            "approve --by you --reason 'initial version'"
        )
        return 0
    cfg = config.load(path)
    pending = [p for p in cfg.watched if not baseline.paths(cfg, p)[1].exists()]
    if pending:
        args.config, args.file = str(path), None
        args.by, args.reason = "demo", "initial approved version (demo setup)"
        return cmd_approve(args)
    print("baseline already approved")
    return 0


def cmd_demo_attack(args) -> int:
    if args.scenario == "list":
        for name, function in simulate.SCENARIOS.items():
            print(f"{name:<18} {function.__name__}")
        return 0
    cfg = _config(args)
    for path in cfg.watched:
        description = simulate.apply(path, args.scenario, atomic=args.atomic)
        how = "atomic replace" if args.atomic else "in-place write"
        print(f"[attacker] {path.name}: {description} ({how})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="otguard", description="Detect unapproved changes to PLC (Rockwell L5X) project files."
    )
    parser.add_argument("--version", action="version", version=f"otguard {__version__}")
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG, help="otguard.toml (default: $OTGUARD_CONFIG or ./otguard.toml)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    approve = sub.add_parser("approve", help="make the current file the signed, approved baseline")
    approve.add_argument("file", nargs="?", help="watched file name (default: all)")
    approve.add_argument("--by", required=True, help="who approves")
    approve.add_argument("--reason", required=True, help="why (change ticket, work order)")
    approve.set_defaults(func=cmd_approve)

    check = sub.add_parser("check", help="compare watched files with their baselines once (exit 1 on drift)")
    check.add_argument("file", nargs="?")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    compare = sub.add_parser("diff", help="explain the differences between two L5X files")
    compare.add_argument("approved")
    compare.add_argument("current")
    compare.add_argument("--json", action="store_true")
    compare.set_defaults(func=cmd_diff)

    watch = sub.add_parser("watch", help="run the drift engine")
    watch.set_defaults(func=cmd_watch)

    verify = sub.add_parser("verify-ledger", help="check the alert ledger's hash chain and MACs")
    verify.add_argument("--ledger", help="ledger file (default: from the config)")
    verify.set_defaults(func=cmd_verify_ledger)

    demo = sub.add_parser("demo", help="demo workspace and simulated attacks")
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    init = demo_sub.add_parser("init", help="create a demo workspace with the sample project")
    init.add_argument("dir")
    init.add_argument("--force", action="store_true", help="start over (removes baselines and ledger)")
    init.add_argument("--approve", action="store_true", help="approve the sample if nothing is approved yet")
    init.set_defaults(func=cmd_demo_init)
    attack = demo_sub.add_parser("attack", help="apply a scenario to the watched files ('list' to list)")
    attack.add_argument("scenario", choices=[*simulate.SCENARIOS, "list"])
    attack.add_argument("--atomic", action="store_true", help="save via a temporary file and rename")
    attack.set_defaults(func=cmd_demo_attack)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (config.ConfigError, baseline.BaselineError, l5x.ProjectError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
