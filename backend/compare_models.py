#!/usr/bin/env python3
"""
compare_models.py
Runs the same flagged events through each model several times, counts how often each
model breaks the output rules, and times it.

It imports build_prompt() and clean_explanation() from llm_explain.py, so any prompt
change made there is picked up automatically. It sets the model itself, so the MODEL
lines in llm_explain.py do not need to be edited, and it never touches alerts.json.

Run from the backend folder (Ollama must be running and both models pulled):
    python compare_models.py            # 3 runs per model
    python compare_models.py --runs 5

Output:
    printed summary + ../model_comparison/comparison_runs.csv
"""

import argparse
import os
import re
import time
import pandas as pd
import llm_explain

MODELS = {
    "llama":      "llama3.2:3b",
    "foundation": "dr-ry/foundation-sec-8b-instruct-chat-GGUF",
}

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model_comparison")

SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


def sentences(text):
    return [s for s in SENT_SPLIT.split(text.strip()) if s]


# Format problems, counted on the RAW model output (before clean_explanation)
RAW_CHECKS = {
    "preamble":          lambda raw: bool(re.match(r"^\s*Here(?:'s| is| are)", raw, re.I)),
    "sentence_labels":   lambda raw: bool(re.search(r"Sentence\s*[12]\s*:", raw, re.I)),
    "model_added_label": lambda raw: bool(re.match(r"^\s*(RED FLAG|WARNING|NORMAL)\b", raw, re.I)),
    "uses_quotes":       lambda raw: any(q in raw for q in ('"', "\u201c", "\u201d")),
    "not_2_sentences":   lambda raw: len(sentences(raw)) != 2,
    "says_our":          lambda raw: bool(re.search(r"\bour\b", raw, re.I)),
    "says_someone":      lambda raw: bool(re.search(r"\bsomeone\b", raw, re.I)),
}

# Content problems, counted on the CLEANED text (what the user would actually see)
CLEAN_CHECKS = {
    "leaks_ip":           lambda t: bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t)),
    "leaks_port_or_size": lambda t: bool(re.search(r"\bport\s*\d+|\b\d{2,}\s*(?:bytes|KB|MB)\b", t, re.I)),
    "mentions_protocol":  lambda t: bool(re.search(r"\b(TCP|UDP|HTTPS?)\b", t)),
    "calls_it_secure":    lambda t: bool(re.search(r"\bsecure[d]?\s+(connection|protocol|port|channel|web|traffic)", t, re.I)),
    "claims_malicious":   lambda t: bool(re.search(r"malicious|compromised|hacked|known to be bad", t, re.I)),
    "mentions_date":      lambda t: bool(re.search(
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}\b", t)),
    "mentions_ml":        lambda t: bool(re.search(r"anomaly score|machine learning", t, re.I)),
    "no_next_step":       lambda t: len(sentences(t)) < 2,
    # Not a rule violation: tracks how repetitive the advice is
    "update_advice":      lambda t: bool(re.search(r"\bupdate[sd]?\b|firmware|\bpatch", t, re.I)),
}


def timed_chat(model, prompt):
    start = time.perf_counter()
    resp = llm_explain.chat(model=model, messages=[{"role": "user", "content": prompt}])
    return resp.message.content.strip(), time.perf_counter() - start


def main():
    parser = argparse.ArgumentParser(description="Compare language models on flagged events")
    parser.add_argument("--runs", type=int, default=3, help="runs per model (default 3)")
    args = parser.parse_args()

    if llm_explain.chat is None:
        print("[!] The 'ollama' package is not installed. Run: python -m pip install ollama")
        return

    try:
        df = pd.read_csv(llm_explain.FLAGGED_FILE)
    except FileNotFoundError:
        print(f"[!] {llm_explain.FLAGGED_FILE} not found. Run score_flows.py first (from the backend folder).")
        return

    records = []
    for name, model in MODELS.items():
        print(f"\n=== {name}: {model} ===")

        # Warm-up call so model load time is not counted in the timings
        try:
            llm_explain.chat(model=model, messages=[{"role": "user", "content": "Reply with OK."}])
        except Exception as e:
            print(f"[!] Could not load {model} ({e.__class__.__name__}); skipping this model")
            continue

        for run in range(1, args.runs + 1):
            run_seconds = 0.0
            for event_id, (_, row) in enumerate(df.iterrows(), 1):
                prompt = llm_explain.build_prompt(row)
                raw, secs = timed_chat(model, prompt)
                clean = llm_explain.clean_explanation(raw)
                run_seconds += secs

                rec = {"model": name, "run": run, "event": event_id, "seconds": round(secs, 2),
                       "words": len(clean.split()), "raw": raw, "clean": clean}
                for check, fn in RAW_CHECKS.items():
                    rec[check] = int(fn(raw))
                for check, fn in CLEAN_CHECKS.items():
                    rec[check] = int(fn(clean))
                records.append(rec)
            print(f"  run {run}/{args.runs}: {run_seconds:.1f} s for {len(df)} events")

    if not records:
        print("[!] No results to summarize.")
        return

    res = pd.DataFrame(records)
    check_cols = list(RAW_CHECKS) + list(CLEAN_CHECKS)

    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, "comparison_runs.csv")
    res.to_csv(out_path, index=False)

    print("\n" + "=" * 60)
    print(f"SUMMARY ({len(df)} events x {args.runs} runs per model)")
    print("=" * 60)

    per_run = res.groupby(["model", "run"])["seconds"].sum().groupby("model").agg(["mean", "min", "max"]).round(1)
    print("\nSeconds per run (all events):")
    print(per_run.to_string())

    print("\nAverage seconds per alert:")
    print(res.groupby("model")["seconds"].mean().round(2).to_string())

    print("\nAverage words per explanation:")
    print(res.groupby("model")["words"].mean().round(1).to_string())

    print("\nPercent of answers with each problem (lower is better):")
    rates = (res.groupby("model")[check_cols].mean() * 100).round(0).astype(int).T
    print(rates.to_string())

    print("\nAverage number of different answers per event across runs (1 = always the same):")
    print(res.groupby(["model", "event"])["clean"].nunique().groupby("model").mean().round(2).to_string())

    print(f"\n[*] Full per-answer results saved to {out_path}")


if __name__ == "__main__":
    main()