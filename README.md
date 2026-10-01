# OT-Guard — PLC logic drift detector

Watches a Rockwell **L5X** PLC project file and raises a SIEM-ready alert the
moment someone changes the control logic without approval — a flipped safety
interlock, a raised pressure setpoint, an inhibited task — while staying quiet
through the file's own normal churn (export timestamps, live counters, edits to
comments). Every alert says, in an engineer's terms, *what* changed and maps it
to the matching **MITRE ATT&CK for ICS** technique.

```
[!] CRITICAL WaterPlant.L5X: 1 unapproved change(s); most serious:
    contact on Temp_High inverted (XIC -> XIO)   [T0889 Modify Program]
```

![OT-Guard dashboard: a CRITICAL drift alert on WaterPlant.L5X mapped to MITRE ATT&CK for ICS T0889 (Modify Program / Persistence), with a change table and a colour-coded normalized before/after diff, and a sidebar showing the alert ledger's hash chain and MACs verified](docs/dashboard_screenshot.png)

## This is a solo prototype

I built this single-handedly to explore one OT-specific detection gap ahead of
the **Adani Cyber Sanjeevni Hackathon 2026** (Track 2). It is a working
proof-of-concept of the *detection idea*, not a production ICS product.

The idea then grew, with teammates, into a much larger field demo —
**[positromen/Adani-Project-OT](https://github.com/positromen/Adani-Project-OT)**
(a.k.a. *LogicWard / Vigilo*). That team repo is the real hackathon submission:
a two-machine attacker/defender setup running against live hardware (Raspberry
Pi + Modbus), a full SOC dashboard, role-based access control, and two plant
sites (a thermal plant and the GRFICS chemical reactor). Credit for that version
goes to the whole team — **Siddhesh Sakle ([@positromen](https://github.com/positromen))**,
myself (**[@JampaniKomal](https://github.com/JampaniKomal)**), and teammates
([@akshitag001](https://github.com/akshitag001), and others).

**This repo stays what it always was: the original single-author proof the
drift-detection idea started from.** It is deliberately narrow — one file, one
clean defensive pipeline, no attack tooling — so the detection logic is easy to
read and test. If you want the live, multi-site, team-scale demo, go to the repo
linked above.

## The problem

In an OT environment, a silent unauthorized edit to PLC logic can cause real
physical damage: flip a cooling-fan interlock from "run when hot" to "run when
cool", quietly raise a pressure threshold past the point where the relief valve
can save the vessel, or inhibit the task that runs the safety logic at all.

Ordinary IT File Integrity Monitors are the wrong tool for this:

- They either **miss it** — a hash of the whole file tells you *that* it changed,
  never *what*, so an operator can't tell a real attack from a routine re-export.
- Or they **drown you in false positives** — PLC project files carry a lot of
  genuinely volatile data (export dates, software revisions, live timer
  accumulators, scan counters), and a naive monitor alerts on every one.

OT-Guard parses the L5X, separates the *logic* (rungs, setpoints, task
configuration) from the *noise* (volatile metadata and runtime values it is told
to ignore), and alerts only on genuine logic changes.

## What changed from v1 (and why)

The v1 of this repo looked plausible but was unsound in ways that matter for a
security tool. v2 is a ground-up rewrite that fixes each one:

| v1 behaviour | Why it was wrong | v2 |
|---|---|---|
| Re-synced / adopted the current file as the new baseline after an alert | An attacker just had to wait one cycle and their tampered logic *became* the trusted state | The baseline **only** changes through `otguard approve`, which records *who* approved it and *why*, and signs the result |
| Overwrote the monitored file from the baseline at start-up | Destroyed the evidence of any tampering done while the engine was stopped | The engine **never writes** a watched file; at start-up it *reports* drift instead of erasing it |
| Watched the file in place | Missed atomic saves (write-temp-then-rename), the way most editors actually save | Reacts to in-place writes, atomic renames, deletion and re-creation, plus a periodic rescan for events the OS never delivers |
| Tagged every change `T0836` labelled "Modify Control Logic" | That label is the deprecated **T0833**; a logic edit is really **T0889 Modify Program** | Each change gets the technique that actually fits (see the mapping below), from ATT&CK for ICS **v19.2** |
| Stripped volatile *text* only, not attributes; a live counter stored as an attribute would false-positive | The gap defeated the whole "ignore the noise" premise for real files | Normalization works on a declared allow-list of volatile attributes **and** tag members, flattened from the decorated data |
| Hard-coded HMAC secret; stored-XSS in the dashboard | Anyone reading the public repo could forge signatures; attacker-controlled diff text ran in the SOC's browser | Fails closed with no built-in key; the dashboard escapes every attacker-controlled string |

## How it works

```
otguard/
  l5x.py        Parse an L5X into a normalized Project: rungs, tags, setpoints,
                tasks, programs. Strip volatile attributes + tag members and
                documentation, then fingerprint = sha256(structure c14n + values).
                Refuses DOCTYPE / non-L5X input.
  ladder.py     Tokenize ladder text (XIC/XIO/OTE/AFI/GRT/TON...) and explain a
                rung change in words ("contact on Temp_High inverted (XIC -> XIO)").
  diff.py       Semantic diff of two Projects -> a list of Changes, each with a
                location, a plain summary, a severity, and an ATT&CK technique.
  baseline.py   `approve` copies the file and writes a signed manifest
                (file hash, fingerprint, policy hash, approved_by, reason, HMAC).
  ledger.py     Append-only JSONL alert log, hash-chained and HMAC'd per line.
  monitor.py    The engine: verify baselines, check every file at start-up, then
                watch (watchdog) + periodic rescan. Writes ECS-shaped events.
  config.py     otguard.toml: what to watch, what counts as volatile. The HMAC
                key comes from $OT_GUARD_SECRET_KEY only — never the file.
  simulate.py   Demo attack scenarios + the sample WaterPlant project.
  dashboard.py  Pure helpers (file status, change rows, escaped diff HTML).
ui/app.py       Read-only Streamlit dashboard over the ledger.
```

The fingerprint is the heart of it: two L5X files that differ only in volatile
noise produce the *same* fingerprint, so a re-export is silent; any real logic
change produces a different one, and the diff explains it.

## ATT&CK for ICS mapping (v19.2)

| Change | Technique | Tactic |
|---|---|---|
| Rung / Structured-Text logic edited, added or removed; program or routine added/removed/disabled | **T0889** Modify Program | Persistence (TA0110) |
| Setpoint / parameter value changed; a `Constant` flag or external-access widened | **T0836** Modify Parameter | Impair Process Control (TA0106) |
| Task inhibited or its scheduling changed | **T0821** Modify Controller Tasking | Execution (TA0104) |
| Alarm limit changed | **T0838** Modify Alarm Settings | Inhibit Response Function (TA0107) |

The deprecated **T0833** (Modify Control Logic) is deliberately absent; a test
asserts it never reappears in the bundled data.

## Quick start (Docker)

No local Python needed — the demo runs entirely in containers.

```bash
docker compose up --build        # engine seeds + signs a demo baseline, then watches; dashboard on 127.0.0.1:8501
```

Then, in another terminal, play attacker and watch the engine and dashboard react:

```bash
docker compose run --rm attacker                     # invert a safety contact
docker compose run --rm attacker demo attack list    # list every scenario
docker compose run --rm attacker demo attack raise-setpoint
```

Open **http://127.0.0.1:8501** for the read-only dashboard, then
`docker compose --profile tools down -v` to stop and remove everything.

The compose file sets a public demo `OT_GUARD_SECRET_KEY` on purpose. It is what
signs the baselines and the ledger, so a real deployment supplies its own secret
(a secrets manager, or an uncommitted `.env`) and never reuses this one.

## CLI

Installed as `otguard` (`pip install .` or `.[dashboard]` for the UI):

```bash
otguard demo init ./demo --approve            # make a sandbox with a signed baseline
otguard --config ./demo/otguard.toml check    # one-shot check; exit 1 on drift, --json for detail
otguard --config ./demo/otguard.toml watch    # run the engine
otguard --config ./demo/otguard.toml approve --by "J. Komal" --reason "WO-7 accepted change"
otguard --config ./demo/otguard.toml verify-ledger
otguard diff approved.L5X current.L5X         # explain the difference between any two files
```

## Attack scenarios

`otguard demo attack <scenario>` applies one of these to the watched file (use
`--atomic` to save via a temporary file and rename, like a real editor):

| Scenario | What it does to the plant | Detected as | Severity |
|---|---|---|---|
| `invert-contact` | Cooling fan now runs only when the motor is **not** hot (XIC→XIO) | T0889 Modify Program | CRITICAL |
| `disable-interlock` | AFI inserted on the pressure interlock rung — the relief valve can never open | T0889 Modify Program | CRITICAL |
| `remove-interlock` | The pressure-interlock rung is deleted outright | T0889 Modify Program | CRITICAL |
| `raise-setpoint` | `High_Pressure_SP` 1000→5000 kPa — the relief valve opens far too late | T0836 Modify Parameter | CRITICAL |
| `inhibit-task` | `MainTask` inhibited — none of the logic runs at all | T0821 Modify Controller Tasking | CRITICAL |
| `shorten-timer` | `Valve_Delay` preset 5000→500 ms — the pump may restart almost immediately | T0836 Modify Parameter | HIGH |
| `unlock-setpoint` | `High_Pressure_SP` loses its `Constant` flag — now writable from outside the controller | T0836 Modify Parameter | HIGH |
| `benign-export` | A later re-export: new timestamps, live values, a timer accumulator, a new comment — **no logic change** | *(nothing — stays quiet)* | — |

`benign-export` is the important one: it proves the normalizer separates noise
from logic, so the tool doesn't cry wolf on routine engineering activity.

## Testing

```bash
pip install .[dev]
pytest          # 67 tests
ruff check .
```

The suite drives the real parser, diff, baseline signing and ledger against real
L5X bytes, runs the monitor against a **real** watchdog observer (in-place edit,
atomic save, deletion, and a rescan path with a deaf observer), exercises every
attack scenario end to end, and renders the Streamlit dashboard via `AppTest` —
including a stored-XSS attempt through attacker-controlled diff text.

## Known limitations

This is a prototype of one detection idea, not a complete ICS security product:

- **L5X files only.** It diffs Rockwell L5X exports. Siemens, CODESYS and other
  vendors use entirely different formats and aren't parsed.
- **File-level, not live controller memory.** It watches a project file on disk.
  It does not read the running controller, so logic changed live and never
  exported is out of scope — this complements, not replaces, controller-level
  monitoring.
- **You must tell it which live values are volatile.** The defaults cover timer
  and counter runtime members; any other genuinely live tag (a process variable
  written every scan) has to be listed under `[normalize]` in `otguard.toml`, or
  it will be treated as a security-relevant value and flagged on every change.
- **Ledger tail truncation.** `verify-ledger` detects any edit to or reordering
  of existing lines via the hash chain and per-line MACs, but an attacker who
  can delete the *most recent* lines wholesale leaves a shorter-but-valid chain;
  catching that needs an external high-water mark (ship each line to a remote
  collector, which is the intended SIEM integration).
- **No authentication on the dashboard.** It is read-only and escapes all alert
  text, but it has no login — fine for a local demo, not for a SOC-facing
  deployment as-is.

## License

MIT — see [LICENSE](LICENSE).
