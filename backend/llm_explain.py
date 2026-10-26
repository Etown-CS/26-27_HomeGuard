#!/usr/bin/env python3
"""
llm_explain.py
Takes flagged/warning events from Isolation Forest and passes them
to Llama 3.2 3B via Ollama to generate plain-language explanations
that a non-technical home user can understand.
Saves output to alerts.json so Teddy's index page can read and display it.

Output:
    alerts.json
"""

import json
import os
import pandas as pd
from datetime import datetime
try:
    from ollama import chat
except ImportError:   # ollama package not installed: fall back to template explanations
    chat = None
    print("[!] 'ollama' package not found; using template explanations instead of the LLM")

### Config
FLAGGED_FILE = "flagged_events.csv"   # output from isolation_forest.py or score_flows.py
# index.html sits in the repo root and fetches alerts.json from there
ALERTS_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "alerts.json")
MODEL        = "llama3.2:3b"

# TODO: Once Kylie pushes her training data/context file to GitHub,
# load it here and pass it into the system prompt as additional context.
# CONTEXT_FILE = "iot_context.json"


def build_prompt(row):
    """
    Build a structured prompt from a flagged event row.
    This is the structured log that gets sent to the LLM instead of raw packets.
    """
    status    = row.get("status", "unknown").upper()
    src_ip    = row.get("src_ip", "unknown")
    dst_ip    = row.get("dst_ip", "unknown")
    protocol  = row.get("protocol", "unknown")
    dst_port  = row.get("dst_port", "unknown")
    length    = row.get("length", "unknown")
    score     = round(float(row.get("anomaly_score", 0)), 4)
    timestamp = row.get("timestamp", "unknown")

    # score_flows.py adds a short hint about what looked unusual
    reason = row.get("reason", "")
    reason_line = f"\n- What looked unusual: {reason}" if isinstance(reason, str) and reason else ""

    prompt = f"""
You are HomeGuard, a friendly home network security assistant.
Your job is to explain network activity to a non-technical home user in plain, simple language.
Always respond in 2-3 sentences maximum.
Tell the user whether this is NORMAL, a WARNING, or a RED FLAG.
Do not use technical jargon. Do not mention anomaly scores or machine learning.

Here is a network event that was flagged by our detection system:

- Time: {timestamp}
- Device IP: {src_ip}
- Destination IP: {dst_ip}
- Protocol: {protocol}
- Destination Port: {dst_port}
- Packet Size: {length} bytes
- Detection Status: {status}
- Anomaly Score: {score} (the more negative, the more unusual){reason_line}

Please explain this to the user in plain language and tell them what, if anything, they should do.
""".strip()

    return prompt


def fallback_explanation(row):
    """Plain template used when the LLM is not available (no Ollama installed or running)."""
    status = str(row.get("status", "warning")).upper()
    level = "RED FLAG" if status == "FLAGGED" else "WARNING"
    src_ip = row.get("src_ip", "a device")
    dst_ip = row.get("dst_ip", "an unknown address")
    reason = row.get("reason", "")
    reason = reason if isinstance(reason, str) and reason else "behaving differently from normal"
    return (f"{level}: The device at {src_ip} is {reason} while communicating with {dst_ip}. "
            f"This doesn't match your network's normal pattern. If you don't recognize this "
            f"activity, check which device this is and consider restarting or updating it.")


def explain_event(row):
    """Send one flagged event to the LLM and return its plain-language response."""
    if chat is None:
        return fallback_explanation(row)

    prompt = build_prompt(row)
    try:
        response = chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.message.content.strip()
    except Exception as e:   # Ollama not running or model not pulled
        print(f"  [!] LLM unavailable ({e.__class__.__name__}); using template explanation")
        return fallback_explanation(row)


def main():
    print(f"[*] Loading flagged events from {FLAGGED_FILE}...")

    try:
        df = pd.read_csv(FLAGGED_FILE)
    except FileNotFoundError:
        print(f"[!] {FLAGGED_FILE} not found. Run isolation_forest.py first.")
        return

    if df.empty:
        print("[*] No flagged events to explain. Network looks normal.")
        # Write an empty alerts file so the page still loads cleanly
        with open(ALERTS_FILE, "w") as f:
            json.dump([], f)
        return

    print(f"[*] Sending {len(df)} event(s) to {MODEL} for explanation...\n")
    print("─" * 60)

    alerts = []

    for i, (_, row) in enumerate(df.iterrows(), 1):
        status      = row.get("status", "unknown").upper()
        src_ip      = row.get("src_ip", "unknown")
        dst_ip      = row.get("dst_ip", "unknown")
        protocol    = row.get("protocol", "unknown")
        dst_port    = row.get("dst_port", "unknown")
        length      = row.get("length", "unknown")
        timestamp   = row.get("timestamp", datetime.now().isoformat())

        print(f"\n[Event {i}] [{status}] {src_ip} → {dst_ip}")
        print("HomeGuard says:")
        explanation = explain_event(row)
        print(f"  {explanation}")
        print("─" * 60)

        # Build the alert object for the JSON file
        alerts.append({
            "id":          i,
            "status":      status,           # "FLAGGED" or "WARNING"
            "timestamp":   timestamp,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "protocol":    protocol,
            "dst_port":    dst_port,
            "length":      length,
            "explanation": explanation,      # plain-language text from LLM
        })

    # Save all alerts to alerts.json for Teddy's index page to read
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"\n[*] {len(alerts)} alert(s) saved → {ALERTS_FILE}")
    print("[*] Done.")


if __name__ == "__main__":
    main()