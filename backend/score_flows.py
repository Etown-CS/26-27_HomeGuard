#!/usr/bin/env python3
"""
score_flows.py
Scores flow-level traffic with the Isolation Forest trained on the
CIC IoT-DIAD 2024 dataset (see IoT-DIAD24_isolation_forest.ipynb) and writes
flagged events in the same format isolation_forest.py produces, so
llm_explain.py and the dashboard work unchanged.

Pipeline:
    demo_flows.csv -> score_flows.py -> flagged_events.csv
                -> llm_explain.py -> alerts.json -> index.html

Inputs (exported from the notebook):
    homeguard_iforest.joblib   trained model, feature list, thresholds, reference stats
    demo_flows.csv             flows with Timestamp, Src IP, Dst IP + the model's features

Outputs:
    scored_flows.csv           every flow with its score and status
    flagged_events.csv         warning/flagged flows only (read by llm_explain.py)

Run:
    python3 score_flows.py
    python3 score_flows.py --input demo_flows.csv --max-alerts 15
"""

import argparse

import joblib
import numpy as np
import pandas as pd

### Config
MODEL_FILE   = "homeguard_iforest.joblib"
INPUT_FILE   = "demo_flows.csv"
OUTPUT_FILE  = "scored_flows.csv"
FLAGGED_FILE = "flagged_events.csv"
MAX_ALERTS   = 15   # each alert is one LLM call, so keep the demo fast

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}   # IANA protocol numbers

# Plain-language hints for the feature that differs most from normal traffic.
# This is a simple heuristic to give the LLM context, not a full explanation
# of the model's decision.
REASONS = {
    "Flow Packets/s":             "sending packets at an unusually {dir} rate",
    "Flow Bytes/s":               "transferring data at an unusually {dir} speed",
    "Total Length of Fwd Packet": "sending an unusually {dir} amount of data",
    "Total Length of Bwd Packet": "receiving an unusually {dir} amount of data",
    "Total Fwd Packet":           "sending an unusually {dir} number of packets",
    "Total Bwd packets":          "receiving an unusually {dir} number of packets",
    "Flow Duration":              "keeping a connection open for an unusual length of time",
    "SYN Flag Count":             "making an unusual number of connection attempts",
    "RST Flag Count":             "having connections refused or reset",
    "FIN Flag Count":             "closing connections in an unusual way",
    "Dst Port":                   "contacting an unusual service port",
    "Protocol":                   "using an unusual type of network traffic",
}


def signed_log(X):
    """Same transform used in training: compresses very large values, keeps the sign."""
    return np.sign(X) * np.log1p(np.abs(X))


# Fallback phrases by feature family, for features without their own entry above
FAMILY_REASONS = [
    (("Active", "Idle"),         "switching between activity and silence in an unusual pattern"),
    (("Bulk",),                  "sending data in unusually {dir} bursts"),
    (("IAT",),                   "exchanging packets with unusual timing between them"),
    (("Packet Length", "Segment", "Packet Size"),
                                "exchanging packets of an unusual size"),
    (("Init Win", "Seg Size Min"), "setting up its connection in an unusual way"),
    (("Flag",),                  "using unusual connection signals"),
    (("Subflow",),               "sending data in an unusually {dir} number of bursts"),
    (("Down/Up",),               "showing an unusual balance of sending and receiving"),
    (("Bytes/s", "Packets/s"),   "sending traffic at an unusually {dir} rate"),
    (("Act Data",),              "sending an unusually {dir} number of data packets"),
]


def describe(z_row):
    """Turn the most unusual feature of one flow into a short phrase."""
    feat = z_row.abs().idxmax()
    direction = "high" if z_row[feat] > 0 else "low"
    template = REASONS.get(feat)
    if template is None:
        template = next((t for keys, t in FAMILY_REASONS if any(k in feat for k in keys)),
                        "showing unusual network behavior")
    return template.format(dir=direction)


def score(df, bundle):
    cols = bundle["feature_cols"]
    model = bundle["model"]

    # Zero-duration flows give infinite rates; treat them as 0 for scoring
    X = df[cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_log = signed_log(X)

    # score_samples: lower (more negative) = more anomalous
    raw = model.score_samples(X_log)
    anomaly = -raw   # higher = more anomalous, same scale as the thresholds

    status = np.where(anomaly > bundle["flag_threshold"], "flagged",
            np.where(anomaly > bundle["warn_threshold"], "warning", "normal"))

    z = (X_log - bundle["median"]) / bundle["iqr"]

    out = pd.DataFrame({
        "timestamp":     df["Timestamp"],
        "src_ip":        df["Src IP"],
        "dst_ip":        df["Dst IP"],
        "protocol":      df["Protocol"].map(PROTOCOL_NAMES).fillna(df["Protocol"].astype(str)),
        "dst_port":      df["Dst Port"].astype("Int64"),
        "length":        (df["Total Length of Fwd Packet"] + df["Total Length of Bwd Packet"]).round().astype(int),
        "anomaly_score": raw,
        "status":        status,
    })
    out["reason"] = [describe(z.iloc[i]) if s != "normal" else ""
                        for i, s in enumerate(status)]
    if "true_label" in df.columns:   # dataset label, for checking the demo only
        out["true_label"] = df["true_label"].values
    return out


def main():
    parser = argparse.ArgumentParser(description="Score flows with the trained HomeGuard model")
    parser.add_argument("--input", default=INPUT_FILE)
    parser.add_argument("--model", default=MODEL_FILE)
    parser.add_argument("--max-alerts", type=int, default=MAX_ALERTS)
    args = parser.parse_args()

    print(f"[*] Loading model from {args.model}...")
    bundle = joblib.load(args.model)

    print(f"[*] Scoring flows from {args.input}...")
    df = pd.read_csv(args.input)
    missing = [c for c in bundle["feature_cols"] + ["Timestamp", "Src IP", "Dst IP"] if c not in df.columns]
    if missing:
        raise SystemExit(f"[!] Input is missing columns: {missing}")

    scored = score(df, bundle)
    scored.to_csv(OUTPUT_FILE, index=False)
    print(f"[*] {len(scored)} scored flows saved -> {OUTPUT_FILE}")

    flagged = (scored[scored["status"] != "normal"]
            .sort_values("anomaly_score")       # most anomalous first
            .head(args.max_alerts))
    flagged.to_csv(FLAGGED_FILE, index=False)
    print(f"[*] {len(flagged)} flagged/warning event(s) saved -> {FLAGGED_FILE}")

    print("\n── Summary ──────────────────────────────")
    print(scored["status"].value_counts().to_string())

    if "true_label" in scored.columns:
        is_attack = scored["true_label"] != "Benign"
        alerted = scored["status"] != "normal"
        print("\n── Check against dataset labels (demo only) ──")
        print(f"Attacks detected:      {alerted[is_attack].mean():.1%} of {is_attack.sum()}")
        print(f"False alarms (benign): {alerted[~is_attack].mean():.1%} of {(~is_attack).sum()}")


if __name__ == "__main__":
    main()