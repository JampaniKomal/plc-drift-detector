"""OT-Guard dashboard (Streamlit). Read-only: it shows the ledger, it cannot approve anything.

OTGUARD_CONFIG=demo/otguard.toml streamlit run ui/app.py
"""

import os
from pathlib import Path

import pandas as pd
import streamlit as st

from otguard import config, dashboard, ledger

st.set_page_config(page_title="OT-Guard Dashboard", layout="wide")
st.markdown(
    """
    <style>
        .diff-add { color: #3fb950; font-family: monospace; white-space: pre; }
        .diff-remove { color: #f85149; font-family: monospace; white-space: pre; }
        .diff-neutral { color: #8b949e; font-family: monospace; white-space: pre; }
        .diff-container { background: #0d1117; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("OT-Guard: PLC Logic Drift Monitor")
st.caption("Unapproved changes to PLC project files, explained and mapped to MITRE ATT&CK for ICS.")

config_path = os.environ.get("OTGUARD_CONFIG", "otguard.toml")
try:
    cfg = config.load(config_path)
except config.ConfigError as exc:
    st.error(f"Cannot read the configuration: {exc}")
    st.stop()

records = [r for r in ledger.read(cfg.ledger) if "_invalid" not in r]
key = None
try:
    key = config.secret_key(required=False)
except config.ConfigError:
    pass
problems = ledger.verify(cfg.ledger, key)

with st.sidebar:
    st.subheader("Ledger")
    st.write(f"`{Path(cfg.ledger).name}`: {len(records)} records")
    if problems:
        st.error("Ledger integrity check FAILED")
        for problem in problems[:10]:
            st.write(f"- {problem}")
    elif key:
        st.success("Hash chain and MACs verified")
    else:
        st.info("Hash chain linked; MACs not checked (no key in this process)")
    if st.button("Refresh"):
        st.rerun()

status = dashboard.file_status(records, [p.name for p in cfg.watched])
columns = st.columns(max(len(status), 1))
for column, (name, info) in zip(columns, status.items(), strict=False):
    with column:
        state = info.get("state", "OK")
        text = f"**{name}**: {state}"
        if state == "OK":
            st.success(text)
        else:
            st.error(text)
        if info.get("message"):
            st.caption(info["message"])
        approved = info.get("baseline")
        if approved:
            st.caption(
                f"Baseline approved by {approved.get('approved_by')} at {approved.get('approved_at')}: "
                f"{approved.get('reason')}"
            )

alerts = dashboard.alerts(records)
if not alerts:
    st.success("Secure. No unapproved logic changes detected.")
else:
    st.error(f"{len(alerts)} alert(s) recorded")
    for index, record in enumerate(alerts):
        details = record.get("otguard", {})
        techniques = ", ".join(
            f"{t['id']} {t['name']}" for t in record.get("threat", {}).get("technique", [])
        )
        when = record.get("@timestamp", "")[:19]
        title = f"[{when}] {details.get('severity', '')}: {record.get('message', '')}"
        with st.expander(title, expanded=index == 0):
            if techniques:
                tactics = ", ".join(t["name"] for t in record.get("threat", {}).get("tactic", []))
                st.markdown(f"**MITRE ATT&CK for ICS:** {techniques} (tactic: {tactics})")
            rows = dashboard.change_rows(record)
            if rows:
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            if details.get("error"):
                st.code(details["error"])
            if details.get("diff"):
                st.markdown("**Approved vs current (normalized)**")
                st.markdown(dashboard.diff_html(details["diff"]), unsafe_allow_html=True)

with st.expander("All ledger events"):
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "seq": r.get("seq"),
                    "time": r.get("@timestamp"),
                    "action": dashboard.action(r),
                    "severity": r.get("otguard", {}).get("severity"),
                    "message": r.get("message"),
                }
                for r in reversed(records)
            ]
        ),
        hide_index=True,
        width="stretch",
    )

st.markdown("---")
st.caption(
    "OT-Guard | Cyber Sanjeevni prototype | read-only dashboard; approvals go through `otguard approve`"
)
