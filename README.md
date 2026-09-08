# 26-27_HomeGuard

A lightweight intrusion detection system that watches traffic on your home or small-office network and flags suspicious device behavior without needing you to be a security expert.

## What it does

HomeGuard captures network traffic using Scapy/pyshark, extracts flow-level features per device, and runs an anomaly detection model (Isolation Forest or a small autoencoder) to catch behavior that doesn't fit a device's normal pattern.

Example: if your smart camera suddenly starts beaconing out to an unfamiliar IP address, HomeGuard notices.

## Why it's different

Most alerts from security tools are cryptic logs meant for analysts. HomeGuard translates detections into plain language:

"Your smart plug just tried to talk to a server in a country it's never contacted before."

No raw packet dumps, just a clear heads-up and enough context to decide what to do next.

***

HomeGuard aims to sit in the gap between those two: real detection, explained simply.
Here is a link to our wiki! : https://github.com/Etown-CS/26-27_HomeGuard.wiki.git
