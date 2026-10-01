"""otguard.toml: what to watch, where baselines and the ledger live, what is noise.

    [engine]
    baselines = "baselines"
    ledger = "logs/otguard-ledger.jsonl"
    rescan_seconds = 30        # full re-check even if no file event arrives
    settle_seconds = 0.5       # wait for a write to finish before reading

    [normalize]
    volatile_tags = ["*_PV", "Scan_Counter"]   # added to the built-in timer/counter members
    # volatile_attributes = [...]              # replaces the built-in list if given

    [[watch]]
    path = "project/WaterPlant.L5X"

Relative paths are relative to the config file. The HMAC key is never in
the file: it comes from the OT_GUARD_SECRET_KEY environment variable.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .l5x import DEFAULT_VOLATILE_ATTRIBUTES, DEFAULT_VOLATILE_TAGS, Normalization

DEMO_KEY = "demo-local-only-do-not-use-in-production"
KEY_ENV = "OT_GUARD_SECRET_KEY"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    path: Path
    baselines: Path
    ledger: Path
    watched: tuple[Path, ...]
    normalization: Normalization
    rescan_seconds: float = 30.0
    settle_seconds: float = 0.5

    @property
    def policy_sha256(self) -> str:
        """Identifies the normalization rules a baseline was approved under."""
        data = {
            "volatile_attributes": list(self.normalization.volatile_attributes),
            "volatile_tags": list(self.normalization.volatile_tags),
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def load(path: str | Path) -> Config:
    path = Path(path).resolve()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
    base = path.parent
    engine = data.get("engine", {})
    normalize = data.get("normalize", {})
    watched = tuple((base / entry["path"]).resolve() for entry in data.get("watch", []) if "path" in entry)
    if not watched:
        raise ConfigError(f"{path}: no [[watch]] entries with a path")
    names = [p.name for p in watched]
    if len(set(names)) != len(names):
        raise ConfigError(
            f"{path}: watched files must have distinct file names (baselines are stored by name)"
        )
    attributes = tuple(normalize.get("volatile_attributes", DEFAULT_VOLATILE_ATTRIBUTES))
    tags = tuple(dict.fromkeys([*DEFAULT_VOLATILE_TAGS, *normalize.get("volatile_tags", [])]))
    return Config(
        path=path,
        baselines=(base / engine.get("baselines", "baselines")).resolve(),
        ledger=(base / engine.get("ledger", "otguard-ledger.jsonl")).resolve(),
        watched=watched,
        normalization=Normalization(attributes, tags),
        rescan_seconds=float(engine.get("rescan_seconds", 30)),
        settle_seconds=float(engine.get("settle_seconds", 0.5)),
    )


def secret_key(*, required: bool = True) -> bytes | None:
    """The HMAC key from the environment. Fails closed: there is no built-in default."""
    value = os.environ.get(KEY_ENV, "")
    if not value:
        if required:
            raise ConfigError(
                f"{KEY_ENV} is not set. OT-Guard signs baselines and its ledger with this key; "
                "a default in the source would let anyone who has read it forge signatures."
            )
        return None
    if value == DEMO_KEY:
        print(
            f"warning: {KEY_ENV} is the public demo value; use your own secret outside the demo.",
            file=sys.stderr,
        )
    elif len(value) < 16:
        raise ConfigError(f"{KEY_ENV} is too short; use at least 16 characters")
    return value.encode("utf-8")
