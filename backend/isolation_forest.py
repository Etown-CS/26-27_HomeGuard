#!/usr/bin/env python3
"""
isolation_forest.py
Loads network traffic data from a CSV file, extracts numeric features,
trains an Isolation Forest model, scores each row, and labels it as:
    - normal
    - warning
    - flagged

Output:
    scored_traffic.csv
    flagged_events.csv
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_FILE   = "fake_traffic.csv"   # swap this for Kylie's real data file later
OUTPUT_FILE  = "scored_traffic.csv"
FLAGGED_FILE = "flagged_events.csv"

# Isolation Forest settings
CONTAMINATION = 0.05   # we expect roughly 5% of traffic to be anomalous
RANDOM_STATE  = 42

# Score thresholds (Isolation Forest scores range from -1 to 1)
# More negative = more anomalous
WARNING_THRESHOLD = -0.05   # below this → warning
FLAGGED_THRESHOLD = -0.10   # below this → flagged


def load_and_prepare(path):
    """Load CSV and convert columns into numeric features the model can use."""
    df = pd.read_csv(path)

    # Fill any missing values with 0 or empty string
    df.fillna({"src_port": 0, "dst_port": 0, "length": 0,
                "tcp_flags": "", "protocol": "", "info": ""}, inplace=True)

    # Encode protocol as a number (TCP=0, UDP=1, DNS=2, etc.)
    le_protocol = LabelEncoder()
    df["protocol_enc"] = le_protocol.fit_transform(df["protocol"].astype(str))

    # Encode TCP flags as a number
    le_flags = LabelEncoder()
    df["flags_enc"] = le_flags.fit_transform(df["tcp_flags"].astype(str))

    return df


def extract_features(df):
    """Pick the numeric columns the model will train on."""
    features = [
        "src_port",       # unusual source ports can indicate scanning
        "dst_port",       # unexpected destination ports are a red flag
        "length",         # unusually large or small packets stand out
        "protocol_enc",   # sudden protocol changes are suspicious
        "flags_enc",      # unusual TCP flag combinations matter
    ]
    return df[features]


def label_status(score):
    """Convert a raw anomaly score into a human-readable status."""
    if score <= FLAGGED_THRESHOLD:
        return "flagged"
    elif score <= WARNING_THRESHOLD:
        return "warning"
    else:
        return "normal"


def main():
    print(f"[*] Loading data from {INPUT_FILE}...")
    df = load_and_prepare(INPUT_FILE)
    X  = extract_features(df)

    print(f"[*] Training Isolation Forest on {len(df)} rows...")
    model = IsolationForest(contamination=CONTAMINATION, random_state=RANDOM_STATE)
    model.fit(X)

    # Score every row (-1 to 1, lower = more anomalous)
    df["anomaly_score"] = model.decision_function(X)
    df["status"]        = df["anomaly_score"].apply(label_status)

    # Save full scored output
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[*] Scored traffic saved → {OUTPUT_FILE}")

    # Pull out only flagged and warning rows to send to the LLM
    flagged = df[df["status"].isin(["flagged", "warning"])].copy()
    flagged.to_csv(FLAGGED_FILE, index=False)
    print(f"[*] {len(flagged)} flagged/warning event(s) saved → {FLAGGED_FILE}")

    # Print a quick summary
    print("\n── Summary ──────────────────────────────")
    print(df["status"].value_counts().to_string())
    print("\n── Flagged Events ───────────────────────")
    if flagged.empty:
        print("No anomalies detected.")
    else:
        for _, row in flagged.iterrows():
            print(f"  [{row['status'].upper()}] {row['src_ip']} → {row['dst_ip']} "
                  f"| {row['protocol']} | port {row['dst_port']} "
                  f"| {row['length']}B | score: {row['anomaly_score']:.4f}")


if __name__ == "__main__":
    main()