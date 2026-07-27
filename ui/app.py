import streamlit as st
import json
import os

# Configure Page
st.set_page_config(page_title="OT-Guard Dashboard", page_icon="🛡️", layout="wide")

# Custom CSS for UI Cleanliness and Dark Mode
st.markdown("""
    <style>
        .stAlert { padding: 1rem; margin-bottom: 1rem; border-radius: 0.5rem; }
        .diff-add { color: #00ff00; font-family: monospace; }
        .diff-remove { color: #ff0000; font-family: monospace; }
        .diff-neutral { color: #cccccc; font-family: monospace; }
        .diff-container { background: #1e1e1e; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ OT-Guard: PLC Logic Drift Monitor")
st.markdown("Enterprise-grade configuration drift and unauthorized change detection.")

LOG_FILE = os.environ.get("LOG_DIR", "/app/logs") + "/drift_alerts.jsonl"

def load_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line))
    return logs[::-1] # Reverse chronologically (newest first)

logs = load_logs()

if not logs:
    st.success("✅ Secure. No unauthorized logic changes detected.")
else:
    st.error(f"🚨 {len(logs)} Unauthorized Changes Detected!")
    
    for idx, log in enumerate(logs):
        with st.expander(f"[{log['timestamp']}] {log['mitre_tactic']} (Severity: {log['severity']})", expanded=(idx==0)):
            cols = st.columns(3)
            cols[0].metric("Event", log['event_type'])
            cols[1].metric("MITRE Tactic", log['mitre_attack_ics'])
            cols[2].metric("Target File", log['file_path'])
            
            st.markdown("### Visual Diff (Approved vs Altered)")
            
            # Format Diff
            diff_lines = log.get('diff_summary', '').split('\n')
            formatted_diff = ""
            for line in diff_lines:
                if line.startswith('+') and not line.startswith('+++'):
                    formatted_diff += f'<div class="diff-add">{line}</div>'
                elif line.startswith('-') and not line.startswith('---'):
                    formatted_diff += f'<div class="diff-remove">{line}</div>'
                else:
                    formatted_diff += f'<div class="diff-neutral">{line}</div>'
            
            st.markdown(f"<div class='diff-container'>{formatted_diff}</div>", unsafe_allow_html=True)
            
st.markdown("---")
st.caption("OT-Guard | Cyber Sanjeevni | Designed for Real-World OT Reality")
