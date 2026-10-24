#!/usr/bin/env python3
"""
fake_data.py
Generates fake network traffic data that mimics what Teddy's sniffer.py produces.
Includes mostly normal traffic with one obvious anomaly mixed in.

Output:
    fake_traffic.csv
"""

import csv
import random
from datetime import datetime, timedelta

# Match the same fields Teddy's sniffer uses
CSV_FIELDS = [
    "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip",
    "protocol", "src_port", "dst_port", "length", "tcp_flags", "info",
]

# Simulated devices on the home network
DEVICES = [
    {"name": "Smart Camera",    "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.24"},
    {"name": "Smart Plug",      "mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.25"},
    {"name": "Laptop",          "mac": "aa:bb:cc:dd:ee:03", "ip": "192.168.1.10"},
    {"name": "Smart Thermostat","mac": "aa:bb:cc:dd:ee:04", "ip": "192.168.1.26"},
]

# Trusted destination IPs these devices normally talk to
NORMAL_DESTINATIONS = [
    "8.8.8.8",        # Google DNS
    "1.1.1.1",        # Cloudflare DNS
    "192.168.1.1",    # Home router
    "52.94.236.248",  # AWS (normal cloud traffic)
    "172.217.14.206", # Google
]

PROTOCOLS  = ["TCP", "UDP", "DNS"]
TCP_FLAGS  = ["S", "SA", "A", "FA", "PA"]

def random_timestamp(start, i):
    return (start + timedelta(seconds=i * random.uniform(0.5, 2.0))).isoformat(timespec="milliseconds")

def normal_row(device, start, i):
    protocol = random.choice(PROTOCOLS)
    return {
        "timestamp": random_timestamp(start, i),
        "src_mac":   device["mac"],
        "dst_mac":   "ff:ff:ff:ff:ff:ff",
        "src_ip":    device["ip"],
        "dst_ip":    random.choice(NORMAL_DESTINATIONS),
        "protocol":  protocol,
        "src_port":  random.randint(1024, 65535),
        "dst_port":  443 if protocol == "TCP" else 53,
        "length":    random.randint(60, 800),
        "tcp_flags": random.choice(TCP_FLAGS) if protocol == "TCP" else "",
        "info":      "",
    }

def anomaly_row(device, start, i):
    """
    One obvious anomaly: the smart camera sends a huge packet
    to a suspicious foreign IP it has never contacted before.
    """
    return {
        "timestamp": random_timestamp(start, i),
        "src_mac":   device["mac"],
        "dst_mac":   "ff:ff:ff:ff:ff:ff",
        "src_ip":    device["ip"],
        "dst_ip":    "185.220.101.47",   # suspicious IP (Tor exit node range)
        "protocol":  "TCP",
        "src_port":  random.randint(1024, 65535),
        "dst_port":  8080,               # unusual port for a camera
        "length":    9999,               # unusually large packet
        "tcp_flags": "PA",
        "info":      "ANOMALY: large packet to unknown foreign IP",
    }

def main():
    start     = datetime.now()
    camera    = DEVICES[0]   # Smart Camera is our anomaly device
    rows      = []

    # Generate 49 normal rows across all devices
    for i in range(49):
        device = random.choice(DEVICES)
        rows.append(normal_row(device, start, i))

    # Inject one anomaly from the smart camera at position 25
    rows.insert(25, anomaly_row(camera, start, 25))

    # Write to CSV
    with open("fake_traffic.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] Generated {len(rows)} rows → fake_traffic.csv")
    print(f"[*] Anomaly injected at row 26 (Smart Camera → 185.220.101.47)")

if __name__ == "__main__":
    main()