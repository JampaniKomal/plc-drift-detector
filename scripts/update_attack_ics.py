"""Regenerate otguard/data/attack_ics.json from MITRE's ATT&CK for ICS STIX bundle.

    python scripts/update_attack_ics.py path/to/ics-attack.json

Download the bundle from
https://github.com/mitre-attack/attack-stix-data/blob/master/ics-attack/ics-attack.json
It keeps only the techniques OT-Guard reports, and fails if one of them is
revoked or deprecated in the bundle.
"""

import json
import sys
from pathlib import Path

USED = ("T0889", "T0836", "T0821", "T0838")
OUT = Path(__file__).resolve().parent.parent / "otguard" / "data" / "attack_ics.json"


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def main(path):
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = bundle["objects"]
    version = next(o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection")
    tactics = {
        o["x_mitre_shortname"]: {"id": external_id(o), "name": o["name"]}
        for o in objects
        if o["type"] == "x-mitre-tactic"
    }
    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern" or external_id(obj) not in USED:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            sys.exit(f"{external_id(obj)} is revoked or deprecated in ATT&CK for ICS {version}")
        techniques[external_id(obj)] = {
            "name": obj["name"],
            "tactics": [tactics[p["phase_name"]] for p in obj.get("kill_chain_phases", [])],
        }
    missing = set(USED) - set(techniques)
    if missing:
        sys.exit(f"not found in the bundle: {sorted(missing)}")
    OUT.write_text(
        json.dumps({"attack_ics_version": version, "techniques": techniques}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {OUT} (ATT&CK for ICS {version})")


if __name__ == "__main__":
    main(sys.argv[1])
