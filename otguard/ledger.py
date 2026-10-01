"""The alert ledger: JSON Lines a SIEM can ingest, chained and signed.

Each record carries ``seq``, the previous record's MAC in ``prev``, and its
own HMAC-SHA256 in ``mac``. Editing, deleting or reordering a record breaks
the chain, and forging one needs the key. Field names follow the Elastic
Common Schema where one exists (``@timestamp``, ``event.*``, ``file.*``,
``threat.*``), so Wazuh, Splunk or Elastic can ingest the file as it is.

Limitation: removing records from the end leaves a valid shorter chain.
Ship the ledger to the SIEM as it is written so the copy there is the anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

GENESIS = "0" * 64


def _mac(record: dict, key: bytes) -> str:
    body = json.dumps({k: v for k, v in record.items() if k != "mac"}, sort_keys=True).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


class Ledger:
    def __init__(self, path: Path, key: bytes):
        self.path = Path(path)
        self.key = key
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        for record in read(self.path):
            self._seq, self._prev = record.get("seq", self._seq), record.get("mac", self._prev)

    def append(self, event: dict) -> dict:
        with self._lock:
            record = {
                "@timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                **event,
                "seq": self._seq + 1,
                "prev": self._prev,
            }
            record["mac"] = _mac(record, self.key)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._seq, self._prev = record["seq"], record["mac"]
            return record


def read(path: Path) -> Iterator[dict]:
    """Records in order; lines that are not JSON objects are yielded as {"_invalid": line}."""
    try:
        handle = open(path, encoding="utf-8")
    except FileNotFoundError:
        return
    with handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None
            yield record if isinstance(record, dict) else {"_invalid": number}


def verify(path: Path, key: bytes | None) -> list[str]:
    """Problems with the chain (empty when intact). Without a key only the linkage is checked."""
    problems: list[str] = []
    seq, prev = 0, GENESIS
    for record in read(path):
        if "_invalid" in record:
            problems.append(f"line {record['_invalid']}: not a JSON record")
            continue
        number = record.get("seq")
        if number != seq + 1:
            problems.append(f"record {number}: expected sequence number {seq + 1}")
        if record.get("prev") != prev:
            problems.append(f"record {number}: does not link to the previous record")
        if key is not None and not hmac.compare_digest(str(record.get("mac", "")), _mac(record, key)):
            problems.append(f"record {number}: MAC does not match (edited, or another key)")
        seq, prev = number if isinstance(number, int) else seq + 1, record.get("mac", "")
    return problems
