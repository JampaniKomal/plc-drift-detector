# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-01

A ground-up rewrite. v1 demonstrated the idea but was unsound as a security
tool; v2 fixes the soundness bugs and turns the detector into something whose
output an OT engineer can actually read and trust. The *soul* is unchanged: a
defensive, single-file PLC logic-drift detector built for the Adani Cyber
Sanjeevni Hackathon 2026 exploration. This repo stays the solo prototype; the
team field version lives at
[positromen/Adani-Project-OT](https://github.com/positromen/Adani-Project-OT).

### Fixed (the reasons for the rewrite)
- **Baseline could be silently poisoned.** v1 adopted the current file as the
  new trusted state after an alert, so an attacker only had to outlast one
  cycle. The baseline now changes *only* through `otguard approve`, which
  records who approved it and why and signs the result.
- **Start-up destroyed evidence.** v1 overwrote the monitored file from the
  baseline at launch, erasing tampering done while it was stopped. The engine
  now never writes a watched file and reports pre-existing drift instead.
- **Atomic saves were missed.** v1 watched the file in place and missed the
  write-temp-then-rename pattern most editors use. v2 handles in-place writes,
  atomic renames, deletion and re-creation, plus a periodic rescan.
- **Wrong ATT&CK mapping.** v1 tagged everything `T0836` under the label
  "Modify Control Logic" — which is the deprecated **T0833**. Changes are now
  mapped to the technique that fits (T0889 / T0836 / T0821 / T0838) from ATT&CK
  for ICS **v19.2**, with a test guarding against T0833 reappearing.
- **Volatile stripping ignored attributes.** v1 cleared element text only, so a
  live value stored as an attribute would false-positive. Normalization now uses
  a declared allow-list of volatile attributes and tag members.

### Added
- **Semantic diff.** Rung-, setpoint-, task-, program- and tag-level changes,
  each with a human-readable summary, a severity, and an ATT&CK-for-ICS
  technique; anything outside the understood parts is still reported as an
  unclassified change so the fingerprint and the explanation never disagree.
- **Signed baselines** (`otguard approve`): a manifest with the file hash,
  normalized fingerprint, normalization-policy hash, approver, reason and HMAC.
- **Tamper-evident ledger**: append-only JSONL, hash-chained and HMAC'd per
  line, in Elastic Common Schema shape; `otguard verify-ledger` checks it.
- **Eight demo scenarios** (`otguard demo attack ...`), including `benign-export`
  which must *not* alert, proving noise is separated from logic.
- **Read-only Streamlit dashboard** that escapes all attacker-controlled text.
- **Docker Compose demo** (engine + dashboard + on-demand attacker) and a
  `otguard` CLI (`approve`, `check`, `watch`, `diff`, `verify-ledger`, `demo`).
- **67 tests** (real watchdog observer, real L5X bytes, AppTest dashboard render)
  and a clean `ruff` run.

### Security
- Fails closed: the HMAC key comes only from `$OT_GUARD_SECRET_KEY`, never a
  built-in default. Refuses `DOCTYPE` and oversized or non-L5X input. The
  dashboard HTML-escapes every value drawn from alert data.

## [1.0.0] - earlier
- Initial proof-of-concept: XML normalization + HMAC signing, a watchdog
  monitor, a JSONL alert log, a Streamlit diff view, and a Docker demo.
