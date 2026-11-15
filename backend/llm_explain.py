#!/usr/bin/env python3
"""
llm_explain.py
Takes flagged/warning events from the Isolation Forest (flagged_events.csv), asks the LLM
(via Ollama) to write a plain-language explanation for each NEW event, and saves the result
to the Oracle database (tables: flagged, devices). It no longer writes alerts.json.

The severity label (RED FLAG / WARNING / NORMAL) comes from the detector's
status, not from the language model. The model only writes the explanation.

How it runs:
    - database/app.py imports this file and calls process_new_events() in the background
      when the server starts (and again after each sign-up or login).
    - It can also be run by hand:   python3 backend/llm_explain.py

Events that are already in the database are skipped, so the LLM is only called for new ones.
Settings (database/.env, optional):
    EVENTS_OWNER_EMAIL   save events only for this account (default: every account)
    FLAGGED_CSV          path to the CSV (default: backend/flagged_events.csv)
"""

import ipaddress
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent / "database"))   # so "import db" works from here
import db  # noqa: E402  (database/db.py: Oracle connection and queries)

try:
    from ollama import chat
except ImportError:   # ollama package not installed: fall back to template explanations
    chat = None
    print("[!] 'ollama' package not found; using template explanations instead of the LLM")

### Config
FLAGGED_FILE = os.getenv("FLAGGED_CSV") or str(BASE / "flagged_events.csv")   # output from score_flows.py
# MODEL = "dr-ry/foundation-sec-8b-instruct-chat-GGUF"
MODEL = "llama3.2:3b"

# TODO: Once Kylie pushes her training data/context file to GitHub,
# load it here and pass it into the system prompt as additional context.
# CONTEXT_FILE = "iot_context.json"

_llm_unavailable = False   # set when Ollama can't be reached, so one run doesn't retry for every event


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


def explain_text(row):
    """Return just the explanation text (no label). Uses the template if the LLM is not available."""
    global _llm_unavailable
    if chat is None or _llm_unavailable:
        return fallback_explanation(row)

    try:
        response = chat(
            model=MODEL,
            messages=[{"role": "user", "content": build_prompt(row)}],
        )
        return clean_explanation(response.message.content)
    except Exception as e:   # Ollama not running or model not pulled
        _llm_unavailable = True
        print(f"  [!] LLM unavailable ({e.__class__.__name__}); saving template explanations for this run.")
        print("      Start Ollama (and run: ollama pull llama3.2:3b) before the next run for real explanations.")
        return fallback_explanation(row)


def explain_event(row):
    """Return 'LABEL: explanation', with the label set by the detector."""
    return f"{get_label(row.get('status', 'warning'))}: {explain_text(row)}"


# ---- helpers for saving to the database ----
TS_FORMATS = ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S")


def parse_timestamp(value):
    """CSV timestamps look like '14/02/2023 12:52:02 PM' (dataset) or ISO (live sniffer)."""
    text = str(value or "").strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return datetime(1970, 1, 1)   # fixed value, so an unreadable time never makes an event look new again


def to_int(value):
    return None if pd.isna(value) else int(value)


def to_float(value):
    return None if pd.isna(value) else float(value)


def db_status(status):
    """The database stores FLAGGED / REVIEW / NORMAL."""
    s = str(status).strip().lower()
    if s == "flagged":
        return "FLAGGED"
    if s == "normal":
        return "NORMAL"
    return "REVIEW"   # "warning" in the CSV


def process_new_events(csv_path=None, owner_email=None):
    """
    Read the flagged-events CSV, explain every event that is not in the database yet,
    and save it (plus its source device) for each target account.
    Returns {"new_events": n, "saved": n, "accounts": n}.
    """
    global _llm_unavailable
    csv_path = csv_path or FLAGGED_FILE
    owner_email = os.getenv("EVENTS_OWNER_EMAIL", "") if owner_email is None else owner_email
    summary = {"new_events": 0, "saved": 0, "accounts": 0}

    print(f"[*] Loading flagged events from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"[!] {csv_path} not found. Run score_flows.py first.")
        return summary
    if df.empty:
        print("[*] No flagged events to explain. Network looks normal.")
        return summary

    user_ids = db.get_target_user_ids(owner_email)
    if not user_ids:
        print("[*] No account exists yet. Events will be imported after the first sign-up.")
        return summary
    summary["accounts"] = len(user_ids)

    _llm_unavailable = False   # try the LLM again on every run
    existing = {uid: db.existing_event_keys(uid) for uid in user_ids}
    explained = {}             # each event is explained once and shared between accounts

    for i, (_, row) in enumerate(df.iterrows(), 1):
        src_ip = str(row.get("src_ip", "")).strip()
        dst_ip = str(row.get("dst_ip", "")).strip()
        if not src_ip or not dst_ip or src_ip == "nan" or dst_ip == "nan":
            print(f"[!] Row {i}: missing src_ip or dst_ip, skipped")
            continue

        event_time = parse_timestamp(row.get("timestamp"))
        dst_port = to_int(row.get("dst_port"))
        length = to_int(row.get("length"))
        key = db.event_key(event_time, src_ip, dst_ip, dst_port, length)

        missing = [uid for uid in user_ids if key not in existing[uid]]
        if not missing:
            continue                                   # already saved: no LLM call

        status = db_status(row.get("status"))
        text = explained.get(key) or db.find_explanation(key)
        if not text:
            print(f"\n[Event {i}] [{status}] {src_ip} -> {dst_ip}")
            text = explain_text(row)
            print(f"  HomeGuard says: {text}")
        explained[key] = text

        protocol = row.get("protocol")
        protocol = None if pd.isna(protocol) else str(protocol)
        for uid in missing:
            device_id = db.get_or_create_device(uid, src_ip, event_time)
            db.save_flagged(uid, device_id, status, event_time, src_ip, dst_ip, protocol,
                            dst_port, length, to_float(row.get("anomaly_score")), text)
            existing[uid].add(key)
            summary["saved"] += 1
        summary["new_events"] += 1

    print(f"[*] {summary['new_events']} new event(s) saved to the database for {summary['accounts']} account(s).")
    return summary


def main():
    process_new_events()
    print("[*] Done.")


if __name__ == "__main__":
    main()