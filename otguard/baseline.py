"""Approved baselines: the only way the "known good" project changes.

``approve`` stores a copy of the project and a manifest saying who approved
it, when, why, and under which normalization policy, signed with HMAC-SHA256.
The engine verifies the manifest and the copy before it trusts either, so a
baseline edited while the engine was stopped is caught (unless the editor
also holds the key).

The engine never approves anything by itself and never writes to a watched
file: a detected change stays a change until a person approves it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from . import l5x
from .config import Config

FORMAT = "otguard-baseline/1"


class BaselineError(Exception):
    """A baseline is missing, unsigned, tampered with, or approved under another policy."""


def paths(config: Config, watched: Path) -> tuple[Path, Path]:
    return config.baselines / watched.name, config.baselines / f"{watched.name}.manifest.json"


def _sign(manifest: dict, key: bytes) -> str:
    body = json.dumps({k: v for k, v in manifest.items() if k != "hmac"}, sort_keys=True).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def approve(config: Config, watched: Path, key: bytes, *, by: str, reason: str) -> dict:
    """Make the current content of ``watched`` the approved baseline."""
    if not by.strip() or not reason.strip():
        raise BaselineError("approval needs a name (--by) and a reason (--reason)")
    project = l5x.load(watched, config.normalization)  # refuse to approve an unreadable file
    copy, manifest_path = paths(config, watched)
    config.baselines.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(watched, copy)
    manifest = {
        "format": FORMAT,
        "file": watched.name,
        "file_sha256": hashlib.sha256(copy.read_bytes()).hexdigest(),
        "fingerprint": project.fingerprint,
        "policy_sha256": config.policy_sha256,
        "approved_by": by.strip(),
        "reason": reason.strip(),
        "approved_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    manifest["hmac"] = _sign(manifest, key)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def read_manifest(config: Config, watched: Path) -> dict:
    _, manifest_path = paths(config, watched)
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BaselineError(f"no approved baseline for {watched.name}; run: otguard approve") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"{manifest_path}: unreadable manifest ({exc})") from None


def load_verified(config: Config, watched: Path, key: bytes) -> tuple[l5x.Project, dict]:
    """The approved project, after checking the manifest signature, the copy and the policy."""
    manifest = read_manifest(config, watched)
    copy, _ = paths(config, watched)
    if manifest.get("format") != FORMAT:
        raise BaselineError(f"{watched.name}: unknown manifest format {manifest.get('format')!r}")
    if not hmac.compare_digest(str(manifest.get("hmac", "")), _sign(manifest, key)):
        raise BaselineError(
            f"{watched.name}: baseline manifest signature is invalid (edited, or another key)"
        )
    try:
        data = copy.read_bytes()
    except OSError:
        raise BaselineError(f"{watched.name}: approved copy {copy} is missing") from None
    if hashlib.sha256(data).hexdigest() != manifest["file_sha256"]:
        raise BaselineError(f"{watched.name}: approved copy does not match its signed hash (tampered)")
    if manifest["policy_sha256"] != config.policy_sha256:
        raise BaselineError(
            f"{watched.name}: the normalization policy changed since approval; review it and approve again"
        )
    project = l5x.loads(data, str(copy), config.normalization)
    if project.fingerprint != manifest["fingerprint"]:
        raise BaselineError(f"{watched.name}: fingerprint of the approved copy does not match the manifest")
    return project, manifest
