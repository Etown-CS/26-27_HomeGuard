

HomeGuard aims to sit in the gap between those two: real detection, explained simply.
Here is a link to our wiki! : https://github.com/Etown-CS/26-27_HomeGuard.wiki.git

# HomeGuard

A lightweight intrusion detection system that watches traffic on your home or small-office network and flags suspicious device behavior without needing you to be a security expert. HomeGuard captures network traffic using Scapy/pyshark, extracts flow-level features per device, and runs an anomaly detection model (Isolation Forest or a small autoencoder) to catch behavior that doesn't fit a device's normal pattern.
Example: if your smart camera suddenly starts beaconing out to an unfamiliar IP address, HomeGuard notices.

Most alerts from security tools are cryptic logs meant for analysts. HomeGuard translates detections into plain language. No raw packet dumps, just a clear heads-up and enough context to decide what to do next.

## External Requirements

For the Sniffer.py, it needs to run on a Linux CLI:
- pip install scapy
If pip is not installed on your Linux server, run: "sudo apt update && sudo apt install python3-pip -y"

- python3 sniffer.py --list-ifaces
- sudo python3 sniffer.py -i (interface) -c 50 -o capture.csv

## Setup

The setup for the sniffer would just need to be ran before loading on the website locally.

## Running

- sudo python3 sniffer.py -i (interface) -c 50 -o capture.csv

# Deployment

We aim to hopefully be able to deploy this to the real world. We are working on also making sure the website runs smoothly on other devices so the transition when deployed would be much easier.

# Authors

Farnaz (Teddy) Bazyar - bazyarf@etown.edu
Isabella La Face - lafacei@etown.edu
Kylie Ueda - uedak@etown.edu
