#!/usr/bin/env python3
"""
llm_explain.py
Takes flagged/warning events from Isolation Forest and passes them
to Foundation-Sec-8B via Ollama to generate plain-language explanations
that a non-technical home user can understand.
Saves output to alerts.json so Teddy's index page can read and display it.

The severity label (RED FLAG / WARNING / NORMAL) comes from the detector's
status, not from the language model. The model only writes the explanation.

Output:
    alerts.json
"""

import ipaddress
import json
import os
import re
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
# MODEL = "dr-ry/foundation-sec-8b-instruct-chat-GGUF"
MODEL = "llama3.2:3b"

# TODO: Once Kylie pushes her training data/context file to GitHub,
# load it here and pass it into the system prompt as additional context.
# CONTEXT_FILE = "iot_context.json"


def get_label(status):
    """FIX 1: the label is set by the detector's status, not by the LLM."""
    status = str(status).upper()
    if status == "FLAGGED":
        return "RED FLAG"
    if status == "WARNING":
        return "WARNING"
    return "NORMAL"


def destination_location(dst_ip):
    """Say whether the destination is inside the home network or on the internet."""
    try:
        if ipaddress.ip_address(str(dst_ip)).is_private:
            return "another device on the user's own home network"
        return "a server on the internet"
    except ValueError:
        return "an unknown destination"


def build_prompt(row):
    """
    Fixed structure: sentence 1 says what happened, sentence 2 gives one next step.
    The label is added separately by the code. The model is only given whether the
    destination is local or on the internet, plus the detector's 'reason' hint.
    IP addresses, ports, protocol, and packet size are NOT sent, because the dashboard
    card already shows them and the model kept repeating them or calling them "secure".
    """
    dst_ip = row.get("dst_ip", "unknown")

    reason = row.get("reason", "")
    reason_line = f"\n- What looked unusual: {reason}" if isinstance(reason, str) and reason else ""

    facts = [
        "- Source: a device on the home network",
        f"- Destination: {destination_location(dst_ip)}",
    ]
    facts_text = "\n".join(facts) + reason_line

    prompt = f"""
You are HomeGuard, a friendly home network assistant.
Write exactly 2 sentences for a non-technical home user.
The first sentence says what happened in plain words, without IP addresses, ports, or byte counts.
The second sentence gives one simple next step that fits the event.
Do not label or number the sentences.

Rules:
- Do not state a severity label such as NORMAL, WARNING, or RED FLAG. That is added separately.
- Do not start with an introduction such as "Here are two sentences".
- Use only the facts below. Do not invent details.
- Do not say an address is malicious, suspicious, or known to be bad.
- Do not describe any protocol or port as "secure".
- Refer to "a device", not "someone".
- Do not mention dates, times, anomaly scores, or machine learning.
- Do not suggest changing passwords for traffic between two devices on the same home network.

Event facts:
{facts_text}
""".strip()

    return prompt


def fallback_explanation(row):
    """Plain template used when the LLM is not available (no Ollama installed or running)."""
    src_ip = row.get("src_ip", "a device")
    dst_ip = row.get("dst_ip", "an unknown address")
    reason = row.get("reason", "")
    reason = reason if isinstance(reason, str) and reason else "behaving differently from normal"
    return (f"The device at {src_ip} is {reason} while communicating with {dst_ip}. "
            f"This doesn't match your network's normal pattern. If you don't recognize this "
            f"activity, check which device this is and consider restarting or updating it.")


def clean_explanation(text):
    """Remove labels, preambles, quotes, and prefixes, then keep 2 sentences."""
    text = text.strip()

    # Remove a leading severity label the model added anyway
    text = re.sub(r"^\s*(RED FLAG|WARNING|NORMAL)\s*[:\-]?\s*", "", text, flags=re.IGNORECASE)

    # Remove preambles like "Here are two short sentences explaining the event:"
    text = re.sub(r"^\s*Here(?:'s| is| are)[^\n:]*:\s*", "", text, flags=re.IGNORECASE)

    # Remove quotation marks and 'Next step:' prefixes
    text = text.replace('"', "").replace("\u201c", "").replace("\u201d", "")
    text = re.sub(r"\bNext step\s*:\s*", "", text, flags=re.IGNORECASE)

    # FIX 2: the model sometimes writes "our home network" instead of "your"
    text = re.sub(r"\bour\b", "your", text)
    text = re.sub(r"\bOur\b", "Your", text)

    def first_sentence(s):
        s = re.sub(r"\s+", " ", s).strip()
        return re.split(r"(?<=[.!?])\s+", s)[0]

    # If the model labeled its sentences, take the first sentence of each part
    # so the next step is kept instead of being cut off
    parts = re.split(r"\s*Sentence\s*2\s*:\s*", text, flags=re.IGNORECASE)
    if len(parts) > 1:
        part1 = re.sub(r"^\s*Sentence\s*1\s*:\s*", "", parts[0], flags=re.IGNORECASE)
        return f"{first_sentence(part1)} {first_sentence(parts[1])}".strip()

    # Otherwise remove a stray "Sentence 1:" label, then keep the first 2 sentences
    # (splits on punctuation followed by a space, so IPs like 192.168.1.1 stay intact)
    text = re.sub(r"^\s*Sentence\s*1\s*:\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return " ".join(re.split(r"(?<=[.!?])\s+", text)[:2]).strip()


def explain_event(row):
    """Return 'LABEL: explanation', with the label set by the detector."""
    label = get_label(row.get("status", "warning"))

    if chat is None:
        return f"{label}: {fallback_explanation(row)}"

    prompt = build_prompt(row)
    try:
        response = chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        text = clean_explanation(response.message.content)
        return f"{label}: {text}"
    except Exception as e:   # Ollama not running or model not pulled
        print(f"  [!] LLM unavailable ({e.__class__.__name__}); using template explanation")
        return f"{label}: {fallback_explanation(row)}"


def main():
    print(f"[*] Loading flagged events from {FLAGGED_FILE}...")

    try:
        df = pd.read_csv(FLAGGED_FILE)
    except FileNotFoundError:
        print(f"[!] {FLAGGED_FILE} not found. Run score_flows.py first.")
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
        status      = str(row.get("status", "unknown")).upper()
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
            "explanation": explanation,      # "LABEL: plain-language text"
        })

    # Save all alerts to alerts.json for Teddy's index page to read
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"\n[*] {len(alerts)} alert(s) saved → {ALERTS_FILE}")
    print("[*] Done.")


if __name__ == "__main__":
    main()